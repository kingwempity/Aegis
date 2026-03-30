import React, { useEffect, useState, useRef } from 'react';
import { api } from '../api';
import type { User } from '../api';
import AddUserModal from './AddUserModal';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { UserPlus, MoreVertical, Edit2, Trash2 } from './Icons';

const Users: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [openMenuId, setOpenMenuId] = useState<string | number | null>(null);
  const menuRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});

  // 点击外部关闭下拉菜单
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      // 检查是否点击了任何菜单外部
      const isClickInsideAnyMenu = Object.values(menuRefs.current).some(
        ref => ref && ref.contains(target)
      );
      if (!isClickInsideAnyMenu) {
        setOpenMenuId(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleDeleteUser = async (user: User) => {
    if (!window.confirm(`确定要删除用户「${user.username}」吗？`)) return;
    try {
      const response = await fetch(`/api/v1/users/${user.id}`, { method: 'DELETE' });
      if (!response.ok) {
        throw new Error('删除用户失败');
      }
      setOpenMenuId(null);
      fetchData();
    } catch (e: any) {
      alert(e?.message || '删除用户失败');
    }
  };

  const handleEditUser = (user: User) => {
    setEditingUser(user);
    setIsModalOpen(true);
    setOpenMenuId(null);
  };

  const handleToggleMenu = (userId: string | number) => {
    setOpenMenuId(prev => prev === userId ? null : userId);
  };

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

  const handleCloseModal = () => {
    setIsModalOpen(false);
    setEditingUser(null);
  };

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">用户管理</h2>
        <button 
          onClick={() => { setEditingUser(null); setIsModalOpen(true); }}
          className="px-6 py-2.5 bg-[#ff6b00] text-white rounded-xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 flex items-center gap-2"
        >
          <UserPlus size={16} strokeWidth={3} />
          添加用户
        </button>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-visible">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100 rounded-t-2xl">
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
            ) : users.length === 0 ? (
              <tr><td colSpan={5} className="px-8 py-12 text-center text-gray-400">暂无用户数据</td></tr>
            ) : (
              users.map((user) => {
                const userId = String(user.id); // 统一转为字符串比较
                const isOpen = openMenuId === userId;
                
                return (
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
                      <div 
                        className="relative inline-block" 
                        ref={el => { menuRefs.current[userId] = el; }}
                      >
                        <button 
                          onClick={() => handleToggleMenu(userId)}
                          className="text-gray-400 hover:text-[#ff6b00] transition-colors p-1 rounded hover:bg-gray-100"
                          type="button"
                        >
                          <MoreVertical size={20} />
                        </button>
                        
                        {/* 下拉菜单 */}
                        {isOpen && (
                          <div className="absolute right-0 top-full mt-1 w-36 bg-white rounded-lg shadow-lg border border-gray-100 py-1 z-50">
                            <button
                              type="button"
                              onClick={() => handleEditUser(user)}
                              className="w-full px-4 py-2.5 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
                            >
                              <Edit2 size={16} />
                              编辑用户
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteUser(user)}
                              className="w-full px-4 py-2.5 text-left text-sm text-red-600 hover:bg-red-50 flex items-center gap-2 transition-colors"
                            >
                              <Trash2 size={16} />
                              删除用户
                            </button>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      <AddUserModal 
        isOpen={isModalOpen} 
        onClose={handleCloseModal} 
        onSuccess={fetchData}
        editingUser={editingUser}
      />
    </div>
  );
};

export default Users;