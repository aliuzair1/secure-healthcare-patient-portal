"""detection/ml_interface.py — Pluggable ML / Anomaly Engine (Stubs)"""
from __future__ import annotations
import time
from abc import ABC, abstractmethod
from typing import Any, List, Optional
from config import config
from detection import BaseDetector, DetectionResult, ThreatCategory
from logger import get_logger
logger = get_logger("ml_interface")

class MLModelInterface(ABC):
    @abstractmethod
    def predict(self, feature_vector: List[float]) -> float: ...
    @abstractmethod
    def is_ready(self) -> bool: ...
    @property
    def model_type(self): return self.__class__.__name__

class SklearnModelLoader(MLModelInterface):
    def __init__(self):
        self._model = None; self._ready = False
        if config.ml.model_path:
            try:
                import joblib; self._model = joblib.load(config.ml.model_path); self._ready = True
            except Exception as e: logger.error("sklearn load error: %s", e)
    def predict(self, fv):
        if not self._ready: return 0.0
        try:
            import numpy as np; x = np.array(fv).reshape(1,-1)
            if hasattr(self._model,"predict_proba"):
                p = self._model.predict_proba(x)[0]
                return float(p[1]) if len(p)>1 else float(p[0])
            return max(0.0,min(1.0,float(self._model.predict(x)[0])))
        except Exception as e: logger.warning("sklearn predict: %s",e); return 0.0
    def is_ready(self): return self._ready

class ONNXModelLoader(MLModelInterface):
    def __init__(self):
        self._session = None; self._ready = False
        if config.ml.model_path:
            try:
                import onnxruntime as ort
                self._session = ort.InferenceSession(config.ml.model_path)
                self._input_name = self._session.get_inputs()[0].name; self._ready = True
            except Exception as e: logger.error("ONNX load error: %s", e)
    def predict(self, fv):
        if not self._ready: return 0.0
        try:
            import numpy as np; x = np.array([fv], dtype=np.float32)
            out = self._session.run(None, {self._input_name: x})
            raw = float(out[0][0][1]) if out[0].shape[-1]>1 else float(out[0][0][0])
            return max(0.0, min(1.0, raw))
        except Exception as e: logger.warning("ONNX predict: %s",e); return 0.0
    def is_ready(self): return self._ready

class RESTModelLoader(MLModelInterface):
    def __init__(self):
        self._endpoint = config.ml.rest_endpoint
        self._timeout = config.ml.inference_timeout_ms / 1000.0
        self._ready = bool(self._endpoint)
    def predict(self, fv):
        if not self._ready: return 0.0
        try:
            import requests
            r = requests.post(self._endpoint, json={"features": fv}, timeout=self._timeout)
            return max(0.0, min(1.0, float(r.json().get("score", 0.0))))
        except Exception as e: logger.warning("REST predict: %s",e); return 0.0
    def is_ready(self): return self._ready

_LOADERS = {"sklearn": SklearnModelLoader, "onnx": ONNXModelLoader, "rest": RESTModelLoader}

def build_model():
    if not config.ml.enabled: return None
    cls = _LOADERS.get(config.ml.model_type)
    return cls() if cls else None

class MLEngine(BaseDetector):
    name = "ml_engine"
    def __init__(self): self._model = build_model()
    def is_available(self):
        return config.ml.enabled and self._model is not None and self._model.is_ready()
    def detect(self, nr, fv):
        if not self.is_available(): return []
        if fv.schema_version != config.ml.feature_version:
            logger.warning("Feature schema mismatch — skipping ML"); return []
        t0 = time.perf_counter()
        score = self._model.predict(fv.numeric_vector)
        ms = (time.perf_counter()-t0)*1000
        if ms > config.ml.inference_timeout_ms:
            logger.warning("ML inference %.1f ms (limit %d ms)",ms,config.ml.inference_timeout_ms)
        if score <= 0.05: return []
        return [DetectionResult(score, score>=0.70, ThreatCategory.UNKNOWN, "ML-001",
            f"ML model score={score:.3f}",{"ml_score":score,"inference_ms":round(ms,2)})]

class AnomalyEngine(BaseDetector):
    name = "anomaly_engine"
    def __init__(self):
        self._model = None; self._ready = False
        if config.anomaly.enabled and config.anomaly.baseline_path:
            try:
                import joblib; self._model = joblib.load(config.anomaly.baseline_path); self._ready = True
            except Exception as e: logger.error("Anomaly load: %s",e)
    def is_available(self): return config.anomaly.enabled and self._ready
    def detect(self, nr, fv):
        if not self.is_available(): return []
        try:
            import numpy as np; x = np.array(fv.numeric_vector).reshape(1,-1)
            pred = self._model.predict(x)[0]
            if pred == -1:
                score = 0.60
                if hasattr(self._model,"decision_function"):
                    raw = float(self._model.decision_function(x)[0])
                    score = max(0.0, min(1.0, -raw/5.0))
                return [DetectionResult(score,False,ThreatCategory.ZERO_DAY_ANOMALY,"ANOMALY-001",
                    f"Statistical anomaly ({config.anomaly.algorithm})",{"anomaly_score":score})]
        except Exception as e: logger.warning("Anomaly detect: %s",e)
        return []
