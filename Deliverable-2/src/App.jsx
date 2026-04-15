import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import { ROLES } from './config/constants';
import { ProtectedRoute, RoleGuard, PublicRoute } from './guards/ProtectedRoute';
import DashboardLayout from './components/layout/DashboardLayout';

// Public pages
import Login from './pages/public/Login';
import Register from './pages/public/Register';
import PasswordReset from './pages/public/PasswordReset';
import NotFound from './pages/public/NotFound';

// Patient pages
import PatientDashboard from './pages/patient/PatientDashboard';
import Profile from './pages/patient/Profile';
import Reports from './pages/patient/Reports';
import Appointments from './pages/patient/Appointments';
import PatientMessages from './pages/patient/Messages';

// Doctor pages
import DoctorDashboard from './pages/doctor/DoctorDashboard';
import PatientRoster from './pages/doctor/PatientRoster';
import PatientRecords from './pages/doctor/PatientRecords';
import ClinicalUpdates from './pages/doctor/ClinicalUpdates';
import DoctorMessages from './pages/doctor/DoctorMessages';

// Admin pages
import AdminDashboard from './pages/admin/AdminDashboard';
import UserManagement from './pages/admin/UserManagement';
import DoctorApprovals from './pages/admin/DoctorApprovals';
import PatientAssignment from './pages/admin/PatientAssignment';
import Scheduling from './pages/admin/Scheduling';

function DashboardWrapper({ children }) {
  return <DashboardLayout>{children}</DashboardLayout>;
}

export default function App() {
  const { user, isAuthenticated } = useAuth();

  return (
    <Routes>
      {/* ============ PUBLIC ROUTES ============ */}
      <Route element={<PublicRoute />}>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<PasswordReset />} />
      </Route>

      {/* ============ PROTECTED ROUTES ============ */}
      <Route element={<ProtectedRoute />}>

        {/* ---- Patient Routes ---- */}
        <Route element={<RoleGuard allowedRoles={[ROLES.PATIENT]} />}>
          <Route path="/patient" element={<DashboardWrapper><PatientDashboard /></DashboardWrapper>} />
          <Route path="/patient/profile" element={<DashboardWrapper><Profile /></DashboardWrapper>} />
          <Route path="/patient/reports" element={<DashboardWrapper><Reports /></DashboardWrapper>} />
          <Route path="/patient/appointments" element={<DashboardWrapper><Appointments /></DashboardWrapper>} />
          <Route path="/patient/messages" element={<DashboardWrapper><PatientMessages /></DashboardWrapper>} />
        </Route>

        {/* ---- Doctor Routes ---- */}
        <Route element={<RoleGuard allowedRoles={[ROLES.DOCTOR]} />}>
          <Route path="/doctor" element={<DashboardWrapper><DoctorDashboard /></DashboardWrapper>} />
          <Route path="/doctor/patients" element={<DashboardWrapper><PatientRoster /></DashboardWrapper>} />
          <Route path="/doctor/records" element={<DashboardWrapper><PatientRecords /></DashboardWrapper>} />
          <Route path="/doctor/clinical" element={<DashboardWrapper><ClinicalUpdates /></DashboardWrapper>} />
          <Route path="/doctor/messages" element={<DashboardWrapper><DoctorMessages /></DashboardWrapper>} />
        </Route>

        {/* ---- Admin Routes ---- */}
        <Route element={<RoleGuard allowedRoles={[ROLES.ADMIN]} />}>
          <Route path="/admin" element={<DashboardWrapper><AdminDashboard /></DashboardWrapper>} />
          <Route path="/admin/users" element={<DashboardWrapper><UserManagement /></DashboardWrapper>} />
          <Route path="/admin/approvals" element={<DashboardWrapper><DoctorApprovals /></DashboardWrapper>} />
          <Route path="/admin/assignments" element={<DashboardWrapper><PatientAssignment /></DashboardWrapper>} />
          <Route path="/admin/scheduling" element={<DashboardWrapper><Scheduling /></DashboardWrapper>} />
        </Route>
      </Route>

      {/* ============ ROOT & FALLBACK ============ */}
      <Route path="/" element={
        isAuthenticated && user ? (
          <Navigate to={user.role === ROLES.PATIENT ? '/patient' : user.role === ROLES.DOCTOR ? '/doctor' : '/admin'} replace />
        ) : (
          <Navigate to="/login" replace />
        )
      } />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
