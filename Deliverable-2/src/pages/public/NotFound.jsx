import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-950 px-4">
      <div className="text-center">
        <p className="text-8xl font-bold text-gradient mb-4">404</p>
        <h1 className="text-2xl font-bold text-white mb-2">Page Not Found</h1>
        <p className="text-surface-400 mb-8 max-w-sm">
          The page you're looking for doesn't exist or you don't have permission to access it.
        </p>
        <Link to="/" className="btn-primary inline-block">Return Home</Link>
      </div>
    </div>
  );
}
