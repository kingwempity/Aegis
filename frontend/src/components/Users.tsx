import React, { useEffect, useState } from 'react';
import { api, User } from '../api';
import AddUserModal from './AddUserModal';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { UserPlus, MoreVertical } from './Icons';

const Users: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchData = async () => {
    try {
      const data = await api.getUsers();
      setUsers(data);
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">用户管理</h2>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="px-6 py-2.5 bg-[#ff6b00] text-white rounded-xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 flex items-center gap-2"
        >
          <UserPlus size={16} strokeWidth={3} />
          添加用户
        </button>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">用户名</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">邮箱</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">角色</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">状态</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider text-right">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {loading ? (
              <tr><td colSpan={5} className="px-8 py-12 text-center text-gray-400">加载中...</td></tr>
            ) : (
              users.map((user) => (
                <tr key={user.id} className="hover:bg-gray-50/50 transition-colors">
                  <td className="px-8 py-5">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 bg-gray-100 rounded-full flex items-center justify-center text-[#2d3343] font-bold text-xs">
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      <span className="text-[#2d3343] font-bold text-sm">{user.username}</span>
                    </div>
                  </td>
                  <td className="px-8 py-5 text-gray-500 text-sm">{user.email}</td>
                  <td className="px-8 py-5">
                    <span className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-[10px] font-bold uppercase">{user.role}</span>
                  </td>
                  <td className="px-8 py-5">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${user.status === 'Active' ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                      <span className="text-xs font-bold text-gray-600">{user.status}</span>
                    </div>
                  </td>
                  <td className="px-8 py-5 text-right">
                    <button className="text-gray-400 hover:text-[#ff6b00] transition-colors">
                      <MoreVertical size={20} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <AddUserModal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        onSuccess={fetchData}
      />
    </div>
  );
};

export default Users;
