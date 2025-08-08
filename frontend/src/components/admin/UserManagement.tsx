import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../../lib/api-client';
import type { components } from '../../generated/api';
import { useAuth } from '../../hooks/useAuth';

type User = components['schemas']['UserResponse'];

export function UserManagement() {
  const { loading: authLoading, token } = useAuth();
  const { data, isLoading, error } = useQuery({
    queryKey: ['admin_users', token],
    queryFn: async () => {
      if (!token) {
        throw new Error('No token provided');
      }
      const { data, error } = await apiClient.GET('/api/admin/users', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (error) {
        throw new Error(error.error);
      }
      return data;
    },
    enabled: !authLoading && !!token,
  });

  if (isLoading || authLoading) {
    return (
      <div className="card">
        <h2>User Management</h2>
        <p>Loading users...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <h2>User Management</h2>
        <p>Error loading users: {error.message}</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>User Management</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Email</th>
            <th>Display Name</th>
            <th>Provider</th>
            <th>State</th>
            <th>Created At</th>
            <th>Last Login</th>
          </tr>
        </thead>
        <tbody>
          {data?.users?.map((user: User) => (
            <tr key={user.id}>
              <td>{user.id}</td>
              <td>{user.email}</td>
              <td>{user.display_name}</td>
              <td>{user.provider}</td>
              <td>{user.state}</td>
              <td>{new Date(user.created_at).toLocaleString()}</td>
              <td>{user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
