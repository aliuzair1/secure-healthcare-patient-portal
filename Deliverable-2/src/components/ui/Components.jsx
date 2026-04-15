export function Spinner({ size = 'md', className = '' }) {
  const sizes = { sm: 'w-4 h-4', md: 'w-8 h-8', lg: 'w-12 h-12' };
  return (
    <div className={`${sizes[size]} border-2 border-primary-500 border-t-transparent rounded-full animate-spin ${className}`} role="status" aria-label="Loading">
      <span className="sr-only">Loading...</span>
    </div>
  );
}

export function PageLoader() {
  return (
    <div className="flex items-center justify-center py-20">
      <div className="flex flex-col items-center gap-4">
        <Spinner size="lg" />
        <p className="text-surface-400 text-sm animate-pulse">Loading…</p>
      </div>
    </div>
  );
}

export function Badge({ children, variant = 'default', className = '' }) {
  const variants = {
    default: 'bg-surface-700/50 text-surface-300',
    primary: 'bg-primary-500/10 text-primary-400 border border-primary-500/20',
    success: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
    warning: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
    danger: 'bg-red-500/10 text-red-400 border border-red-500/20',
    info: 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${variants[variant]} ${className}`}>
      {children}
    </span>
  );
}

export function Card({ children, className = '', hover = false, onClick }) {
  return (
    <div
      className={`${hover ? 'card-hover cursor-pointer' : 'card'} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick() : undefined}
    >
      {children}
    </div>
  );
}

export function StatCard({ icon, label, value, trend, trendUp, className = '' }) {
  return (
    <div className={`stat-card ${className}`}>
      <div className="flex items-center justify-between">
        <div className="w-10 h-10 rounded-xl bg-primary-500/10 flex items-center justify-center text-primary-400">
          {icon}
        </div>
        {trend && (
          <span className={`text-xs font-medium ${trendUp ? 'text-emerald-400' : 'text-red-400'}`}>
            {trendUp ? '↑' : '↓'} {trend}
          </span>
        )}
      </div>
      <div className="mt-3">
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-sm text-surface-400 mt-0.5">{label}</p>
      </div>
    </div>
  );
}

export function Modal({ isOpen, onClose, title, children, size = 'md' }) {
  if (!isOpen) return null;
  const sizes = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl', xl: 'max-w-4xl' };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className={`relative ${sizes[size]} w-full glass rounded-2xl border border-surface-600/20 animate-slide-up max-h-[90vh] flex flex-col`}>
        <div className="flex items-center justify-between p-6 border-b border-surface-700/30">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-surface-400 hover:text-white transition-colors p-1" aria-label="Close dialog">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

export function DataTable({ columns, data, emptyMessage = 'No data available', onRowClick }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-surface-700/30">
      <table className="w-full">
        <thead>
          <tr className="border-b border-surface-700/30 bg-surface-800/30">
            {columns.map((col) => (
              <th key={col.key} className="px-4 py-3 text-left text-xs font-semibold text-surface-400 uppercase tracking-wider">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-700/20">
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-surface-500">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((row, i) => (
              <tr
                key={row.id || i}
                className={`transition-colors ${onRowClick ? 'cursor-pointer hover:bg-surface-800/40' : ''}`}
                onClick={() => onRowClick?.(row)}
              >
                {columns.map((col) => (
                  <td key={col.key} className="px-4 py-3 text-sm text-surface-200">
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export function FileUpload({ onFileSelect, accept, error, label = 'Upload File' }) {
  const handleChange = (e) => {
    const file = e.target.files[0];
    if (file) onFileSelect(file);
  };
  return (
    <div>
      <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-surface-600/30 rounded-xl cursor-pointer hover:border-primary-500/40 transition-colors bg-surface-800/20">
        <div className="flex flex-col items-center">
          <svg className="w-8 h-8 text-surface-400 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
          </svg>
          <span className="text-sm text-surface-400">{label}</span>
        </div>
        <input type="file" className="hidden" onChange={handleChange} accept={accept} />
      </label>
      {error && <p className="mt-1 text-sm text-red-400">{error}</p>}
    </div>
  );
}

export function EmptyState({ icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-2xl bg-surface-800/50 flex items-center justify-center text-surface-500 mb-4">
        {icon}
      </div>
      <h3 className="text-lg font-semibold text-surface-300 mb-1">{title}</h3>
      <p className="text-sm text-surface-500 max-w-sm mb-6">{description}</p>
      {action}
    </div>
  );
}
