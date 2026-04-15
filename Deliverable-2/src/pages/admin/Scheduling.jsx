import { useState, useEffect } from 'react';
import { useToast } from '../../context/ToastContext';
import { PageLoader, Badge } from '../../components/ui/Components';
import { getSchedulingConfig, updateSchedulingConfig } from '../../services/adminService';
import { formatDate } from '../../utils/formatters';

export default function Scheduling() {
  const { showToast } = useToast();
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newBlackout, setNewBlackout] = useState('');

  useEffect(() => {
    async function load() {
      try { setConfig(await getSchedulingConfig()); } catch {}
      setLoading(false);
    }
    load();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSchedulingConfig(config);
      showToast('Scheduling configuration saved.', 'success');
    } catch { showToast('Failed to save.', 'error'); }
    setSaving(false);
  };

  const addBlackout = () => {
    if (!newBlackout) return;
    if (config.blackoutDates.includes(newBlackout)) { showToast('Date already added.', 'warning'); return; }
    setConfig({ ...config, blackoutDates: [...config.blackoutDates, newBlackout].sort() });
    setNewBlackout('');
  };

  const removeBlackout = (date) => {
    setConfig({ ...config, blackoutDates: config.blackoutDates.filter((d) => d !== date) });
  };

  if (loading) return <PageLoader />;

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Scheduling Configuration</h1>
        <p className="text-surface-400 mt-1">Manage appointment slots and system settings</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* General Settings */}
        <div className="card space-y-5">
          <h2 className="text-lg font-semibold text-white">General Settings</h2>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Slot Duration (minutes)</label>
            <input type="number" className="input-secure" value={config.slotDurationMinutes}
              onChange={(e) => setConfig({ ...config, slotDurationMinutes: parseInt(e.target.value) || 30 })} min={15} max={120} />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-300 mb-1.5">Max Appointments Per Day</label>
            <input type="number" className="input-secure" value={config.maxAppointmentsPerDay}
              onChange={(e) => setConfig({ ...config, maxAppointmentsPerDay: parseInt(e.target.value) || 16 })} min={1} max={50} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1.5">Working Hours Start</label>
              <input type="time" className="input-secure" value={config.workingHours.start}
                onChange={(e) => setConfig({ ...config, workingHours: { ...config.workingHours, start: e.target.value } })} />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1.5">Working Hours End</label>
              <input type="time" className="input-secure" value={config.workingHours.end}
                onChange={(e) => setConfig({ ...config, workingHours: { ...config.workingHours, end: e.target.value } })} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1.5">Lunch Break Start</label>
              <input type="time" className="input-secure" value={config.lunchBreak.start}
                onChange={(e) => setConfig({ ...config, lunchBreak: { ...config.lunchBreak, start: e.target.value } })} />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-1.5">Lunch Break End</label>
              <input type="time" className="input-secure" value={config.lunchBreak.end}
                onChange={(e) => setConfig({ ...config, lunchBreak: { ...config.lunchBreak, end: e.target.value } })} />
            </div>
          </div>
        </div>

        {/* Blackout Dates */}
        <div className="card space-y-5">
          <h2 className="text-lg font-semibold text-white">Blackout Dates</h2>
          <p className="text-sm text-surface-400">Dates when no appointments can be scheduled</p>
          <div className="flex gap-3">
            <input type="date" className="input-secure flex-1" value={newBlackout} onChange={(e) => setNewBlackout(e.target.value)} />
            <button onClick={addBlackout} className="btn-primary px-4">Add</button>
          </div>
          <div className="space-y-2">
            {config.blackoutDates.length === 0 ? (
              <p className="text-sm text-surface-500">No blackout dates configured</p>
            ) : config.blackoutDates.map((date) => (
              <div key={date} className="flex items-center justify-between p-3 rounded-xl bg-surface-800/30 border border-surface-700/20">
                <span className="text-sm text-white">{formatDate(date)}</span>
                <button onClick={() => removeBlackout(date)} className="text-sm text-red-400 hover:text-red-300">Remove</button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Current Schedule Overview */}
      <div className="card">
        <h2 className="text-lg font-semibold text-white mb-4">Schedule Overview</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-surface-800/30 text-center">
            <p className="text-2xl font-bold text-primary-400">{config.slotDurationMinutes}</p>
            <p className="text-xs text-surface-400 mt-1">min / slot</p>
          </div>
          <div className="p-4 rounded-xl bg-surface-800/30 text-center">
            <p className="text-2xl font-bold text-primary-400">{config.maxAppointmentsPerDay}</p>
            <p className="text-xs text-surface-400 mt-1">max / day</p>
          </div>
          <div className="p-4 rounded-xl bg-surface-800/30 text-center">
            <p className="text-2xl font-bold text-primary-400">{config.workingHours.start} – {config.workingHours.end}</p>
            <p className="text-xs text-surface-400 mt-1">working hours</p>
          </div>
          <div className="p-4 rounded-xl bg-surface-800/30 text-center">
            <p className="text-2xl font-bold text-amber-400">{config.blackoutDates.length}</p>
            <p className="text-xs text-surface-400 mt-1">blackout dates</p>
          </div>
        </div>
      </div>

      <div className="flex gap-3">
        <button onClick={handleSave} disabled={saving} className="btn-primary">{saving ? 'Saving…' : 'Save Configuration'}</button>
      </div>
    </div>
  );
}
