import { useState, useEffect } from 'react';
import { useToast } from '../../context/ToastContext';
import { PageLoader, DataTable, Badge, Modal } from '../../components/ui/Components';
import { getAllUsers, toggleUserStatus } from '../../services/adminService';
import { formatDate } from '../../utils/formatters';
import { ROLE_LABELS } from '../../config/constants';

export default function UserManagement() {
  const { showToast } = useToast();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    async function load() {
      try { setUsers(await getAllUsers()); } catch {}
      setLoading(false);
    }
    load();
  }, []);

  const handleToggle = async (u) => {
    try {
      await toggleUserStatus(u.id, !u.isActive);
      setUsers(users.map((usr) => usr.id === u.id ? { ...usr, isActive: !usr.isActive } : usr));
      showToast(`User ${!u.isActive ? 'activated' : 'deactivated'}.`, 'success');
    } catch { showToast('Failed to update user.', 'error'); }
  };

  if (loading) return <PageLoader />;

  const filtered = users.filter((u) => {
    const matchesSearch = `${u.firstName} ${u.lastName} ${u.email}`.toLowerCase().includes(search.toLowerCase());
    const matchesRole = roleFilter === 'all' || u.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const columns = [
    { key: 'name', label: 'User', render: (u) => (
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-primary-500/20 flex items-center justify-center text-primary-400 text-xs font-bold">{u.firstName[0]}{u.lastName[0]}</div>
        <div><p className="font-medium text-white">{u.firstName} {u.lastName}</p><p className="text-xs text-surface-500">{u.email}</p></div>
      </div>
    )},
    { key: 'role', label: 'Role', render: (u) => <Badge variant="info">{ROLE_LABELS[u.role]}</Badge> },
    { key: 'status', label: 'Status', render: (u) => <Badge variant={u.isActive ? 'success' : 'danger'}>{u.isActive ? 'Active' : 'Inactive'}</Badge> },
    { key: 'created', label: 'Created', render: (u) => formatDate(u.createdAt) },
    { key: 'actions', label: 'Actions', render: (u) => (
      <div className="flex gap-2">
        <button onClick={(e) => { e.stopPropagation(); setSelectedUser(u); }} className="text-sm text-primary-400 hover:text-primary-300">View</button>
        <button onClick={(e) => { e.stopPropagation(); handleToggle(u); }} className={`text-sm ${u.isActive ? 'text-red-400 hover:text-red-300' : 'text-emerald-400 hover:text-emerald-300'}`}>
          {u.isActive ? 'Deactivate' : 'Activate'}
        </button>
      </div>
    )},
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">User Management</h1>
        <p className="text-surface-400 mt-1">Manage all system user accounts</p>
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg>
          <input className="input-secure pl-10" placeholder="Search users…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex gap-1 p-1 rounded-xl bg-surface-800/40 border border-surface-700/20">
          {['all', 'patient', 'doctor', 'admin'].map((r) => (
            <button key={r} onClick={() => setRoleFilter(r)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all ${roleFilter === r ? 'bg-primary-500/20 text-primary-400' : 'text-surface-400 hover:text-white'}`}>
              {r === 'all' ? 'All' : ROLE_LABELS[r] || r}
            </button>
          ))}
        </div>
        <Badge variant="primary">{filtered.length} user{filtered.length !== 1 ? 's' : ''}</Badge>
      </div>

      <DataTable columns={columns} data={filtered} emptyMessage="No users found" onRowClick={setSelectedUser} />

      <Modal isOpen={!!selectedUser} onClose={() => setSelectedUser(null)} title="User Details">
        {selectedUser && (
          <div className="space-y-4">
            <div className="flex items-center gap-4 mb-4">
              <div className="w-14 h-14 rounded-2xl gradient-primary flex items-center justify-center text-white text-lg font-bold">{selectedUser.firstName[0]}{selectedUser.lastName[0]}</div>
              <div>
                <p className="text-lg font-semibold text-white">{selectedUser.firstName} {selectedUser.lastName}</p>
                <Badge variant="info">{ROLE_LABELS[selectedUser.role]}</Badge>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {[
                ['Email', selectedUser.email],
                ['Phone', selectedUser.phone],
                ['Status', selectedUser.isActive ? 'Active' : 'Inactive'],
                ['Created', formatDate(selectedUser.createdAt)],
                ...(selectedUser.specialty ? [['Specialty', selectedUser.specialty]] : []),
                ...(selectedUser.department ? [['Department', selectedUser.department]] : []),
              ].map(([k, v]) => (
                <div key={k} className="p-3 rounded-xl bg-surface-800/30"><p className="text-xs text-surface-500">{k}</p><p className="text-sm text-white">{v}</p></div>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
