/**
 * 帮助内容管理组件
 * 管理员可以编辑帮助中心的内容
 * 
 * Author: Aegis Architect
 * Created: 2026-02-23
 */

import React, { useEffect, useState, useRef } from 'react';
import { api } from '../api';
import type { HelpContent, HelpContentCreate, HelpContentUpdate } from '../api';
import { Plus, MoreVertical, Edit2, Trash2, BookOpen, X, RefreshCw, Eye, ExternalLink, Shield, FileText, MessageCircle } from './Icons';

// 可用图标列表
const AVAILABLE_ICONS = [
  { name: 'BookOpen', color: '#ff6b00' },
  { name: 'Shield', color: '#3b82f6' },
  { name: 'FileText', color: '#22c55e' },
  { name: 'MessageCircle', color: '#a855f7' },
  { name: 'Settings', color: '#6b7280' },
  { name: 'AlertCircle', color: '#ef4444' },
  { name: 'CheckCircle', color: '#10b981' },
  { name: 'Info', color: '#3b82f6' },
];

// 图标组件映射
const getIconComponent = (iconName: string): React.FC<any> => {
  switch (iconName) {
    case 'Shield': return Shield;
    case 'FileText': return FileText;
    case 'MessageCircle': return MessageCircle;
    default: return BookOpen;
  }
};

interface EditModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  editingContent: HelpContent | null;
}

const EditModal: React.FC<EditModalProps> = ({ isOpen, onClose, onSuccess, editingContent }) => {
  const [formData, setFormData] = useState<HelpContentCreate>({
    key: '',
    title: '',
    description: '',
    content: '',
    icon: 'BookOpen',
    icon_color: '#ff6b00',
    link: '',
    order: 0,
    is_active: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // 当编辑内容变化时，更新表单数据
  useEffect(() => {
    if (editingContent) {
      setFormData({
        key: editingContent.key,
        title: editingContent.title,
        description: editingContent.description || '',
        content: editingContent.content || '',
        icon: editingContent.icon,
        icon_color: editingContent.icon_color,
        link: editingContent.link || '',
        order: editingContent.order,
        is_active: editingContent.is_active,
      });
    } else {
      setFormData({
        key: '',
        title: '',
        description: '',
        content: '',
        icon: 'BookOpen',
        icon_color: '#ff6b00',
        link: '',
        order: 0,
        is_active: true,
      });
    }
    setError('');
  }, [editingContent, isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (editingContent) {
        // 更新
        const updateData: HelpContentUpdate = {
          title: formData.title,
          description: formData.description,
          content: formData.content,
          icon: formData.icon,
          icon_color: formData.icon_color,
          link: formData.link || undefined,
          order: formData.order,
          is_active: formData.is_active,
        };
        await api.updateHelpContent(editingContent.id, updateData);
      } else {
        // 创建
        await api.createHelpContent(formData);
      }
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || '操作失败');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div 
        className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden max-h-[90vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 模态框头部 */}
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between bg-gradient-to-r from-[#ff6b00] to-[#ff8c00]">
          <h2 className="text-xl font-bold text-white">
            {editingContent ? '编辑帮助内容' : '添加帮助内容'}
          </h2>
          <button 
            onClick={onClose}
            className="p-2 hover:bg-white/20 rounded-lg transition-colors"
          >
            <X size={20} className="text-white" />
          </button>
        </div>

        {/* 表单内容 */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto">
          <div className="p-6 space-y-4">
            {error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-600 text-sm">
                {error}
              </div>
            )}

            {/* Key */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                标识键 <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={formData.key}
                onChange={(e) => setFormData({ ...formData, key: e.target.value })}
                disabled={!!editingContent}
                className={`w-full px-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all ${
                  editingContent ? 'bg-gray-100 cursor-not-allowed' : ''
                }`}
                placeholder="如：quick_start, attack_validation_guide"
                required
              />
              <p className="text-xs text-gray-400 mt-1">唯一标识，创建后不可修改</p>
            </div>

            {/* 标题 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                标题 <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all"
                placeholder="显示在帮助卡片的标题"
                required
              />
            </div>

            {/* 描述 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">描述</label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all resize-none"
                rows={2}
                placeholder="简短描述，显示在卡片上"
              />
            </div>

            {/* 详细内容 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">详细内容</label>
              <textarea
                value={formData.content}
                onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all resize-none font-mono text-sm"
                rows={8}
                placeholder="支持 Markdown 格式的详细内容"
              />
              <p className="text-xs text-gray-400 mt-1">支持 Markdown 格式，点击卡片后展示</p>
            </div>

            {/* 图标选择 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">图标</label>
              <div className="flex flex-wrap gap-2">
                {AVAILABLE_ICONS.map((icon) => {
                  const IconComponent = getIconComponent(icon.name);
                  return (
                    <button
                      key={icon.name}
                      type="button"
                      onClick={() => setFormData({ ...formData, icon: icon.name, icon_color: icon.color })}
                      className={`p-3 rounded-lg border-2 transition-all ${
                        formData.icon === icon.name
                          ? 'border-[#ff6b00] bg-[#ff6b00]/10'
                          : 'border-gray-200 hover:border-gray-300'
                      }`}
                    >
                      <IconComponent size={24} style={{ color: icon.color }} />
                    </button>
                  );
                })}
              </div>
            </div>

            {/* 跳转链接 */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">跳转链接</label>
              <input
                type="text"
                value={formData.link}
                onChange={(e) => setFormData({ ...formData, link: e.target.value })}
                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all"
                placeholder="可选，点击卡片时跳转的链接"
              />
            </div>

            {/* 排序和状态 */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">排序</label>
                <input
                  type="number"
                  value={formData.order}
                  onChange={(e) => setFormData({ ...formData, order: parseInt(e.target.value) || 0 })}
                  className="w-full px-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all"
                  min="0"
                />
              </div>
              <div className="flex items-center pt-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.is_active}
                    onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                    className="w-4 h-4 rounded border-gray-300 text-[#ff6b00] focus:ring-[#ff6b00]"
                  />
                  <span className="text-sm text-gray-700">启用</span>
                </label>
              </div>
            </div>
          </div>

          {/* 底部按钮 */}
          <div className="px-6 py-4 border-t border-gray-100 bg-gray-50 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 font-medium transition-colors"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2 bg-[#ff6b00] text-white rounded-lg font-medium hover:bg-[#e66000] transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {loading ? (
                <>
                  <RefreshCw size={16} className="animate-spin" />
                  保存中...
                </>
              ) : (
                '保存'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// 详情查看模态框
const DetailModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  content: HelpContent | null;
}> = ({ isOpen, onClose, content }) => {
  if (!isOpen || !content) return null;

  const IconComponent = getIconComponent(content.icon);

  return (
    <div 
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div 
        className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden max-h-[90vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 模态框头部 */}
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div 
              className="w-10 h-10 rounded-lg flex items-center justify-center"
              style={{ backgroundColor: `${content.icon_color}20` }}
            >
              <IconComponent size={24} style={{ color: content.icon_color }} />
            </div>
            <div>
              <h2 className="text-xl font-bold text-gray-800">{content.title}</h2>
              <p className="text-sm text-gray-500">key: {content.key}</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X size={20} className="text-gray-500" />
          </button>
        </div>

        {/* 内容 */}
        <div className="flex-1 overflow-y-auto p-6">
          {content.description && (
            <p className="text-gray-600 mb-4">{content.description}</p>
          )}
          {content.content && (
            <div className="prose prose-sm max-w-none bg-gray-50 rounded-lg p-4 whitespace-pre-wrap font-mono text-sm">
              {content.content}
            </div>
          )}
          {content.link && (
            <div className="mt-4 pt-4 border-t border-gray-100">
              <p className="text-sm text-gray-500">跳转链接：</p>
              <a 
                href={content.link} 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-[#ff6b00] hover:underline flex items-center gap-1"
              >
                {content.link}
                <ExternalLink size={14} />
              </a>
            </div>
          )}
        </div>

        {/* 底部 */}
        <div className="px-6 py-4 border-t border-gray-100 bg-gray-50 flex justify-between items-center">
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <span>排序: {content.order}</span>
            <span className={`px-2 py-0.5 rounded text-xs ${content.is_active ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-500'}`}>
              {content.is_active ? '已启用' : '已禁用'}
            </span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg font-medium hover:bg-gray-300 transition-colors"
          >
            关闭
          </button>
        </div>
      </div>
    </div>
  );
};

// 主组件
const HelpContentManage: React.FC = () => {
  const [contents, setContents] = useState<HelpContent[]>([]);
  const [loading, setLoading] = useState(true);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [editingContent, setEditingContent] = useState<HelpContent | null>(null);
  const [viewingContent, setViewingContent] = useState<HelpContent | null>(null);
  const [openMenuId, setOpenMenuId] = useState<number | null>(null);
  const [menuDirection, setMenuDirection] = useState<'up' | 'down'>('down');
  const menuRefs = useRef<{ [key: number]: HTMLDivElement | null }>({});

  // 点击外部关闭下拉菜单
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
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

  const fetchData = async () => {
    try {
      setLoading(true);
      const data = await api.getHelpContents(false);
      setContents(data);
    } catch (error) {
      console.error('Error fetching help contents:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleInitDefault = async () => {
    if (!window.confirm('确定要初始化默认帮助内容吗？现有内容不会被覆盖。')) return;
    try {
      const result = await api.initDefaultHelpContents();
      alert(result.message);
      fetchData();
    } catch (err: any) {
      alert(err.message || '初始化失败');
    }
  };

  const handleDelete = async (content: HelpContent) => {
    if (!window.confirm(`确定要删除「${content.title}」吗？`)) return;
    try {
      await api.deleteHelpContent(content.id);
      setOpenMenuId(null);
      fetchData();
    } catch (err: any) {
      alert(err.message || '删除失败');
    }
  };

  const handleEdit = (content: HelpContent) => {
    setEditingContent(content);
    setIsEditModalOpen(true);
    setOpenMenuId(null);
  };

  const handleView = (content: HelpContent) => {
    setViewingContent(content);
    setIsDetailModalOpen(true);
    setOpenMenuId(null);
  };

  const updateMenuDirection = (contentId: number) => {
    const triggerEl = menuRefs.current[contentId];
    if (!triggerEl) {
      setMenuDirection('down');
      return;
    }

    const rect = triggerEl.getBoundingClientRect();
    const estimatedMenuHeight = 132;
    const spaceBelow = window.innerHeight - rect.bottom;
    setMenuDirection(spaceBelow < estimatedMenuHeight ? 'up' : 'down');
  };

  const toggleMenu = (contentId: number) => {
    if (openMenuId === contentId) {
      setOpenMenuId(null);
      return;
    }
    updateMenuDirection(contentId);
    setOpenMenuId(contentId);
  };

  useEffect(() => {
    if (openMenuId === null) return;

    const handleViewportChange = () => updateMenuDirection(openMenuId);
    window.addEventListener('resize', handleViewportChange);
    window.addEventListener('scroll', handleViewportChange, true);

    return () => {
      window.removeEventListener('resize', handleViewportChange);
      window.removeEventListener('scroll', handleViewportChange, true);
    };
  }, [openMenuId]);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-[#2d3343]">帮助内容管理</h2>
          <p className="text-sm text-gray-500 mt-1">管理帮助中心显示的内容卡片</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={handleInitDefault}
            className="px-4 py-2.5 border border-gray-200 text-gray-600 rounded-xl font-medium text-sm hover:bg-gray-50 transition-all flex items-center gap-2"
          >
            <RefreshCw size={16} />
            初始化默认内容
          </button>
          <button 
            onClick={() => { setEditingContent(null); setIsEditModalOpen(true); }}
            className="px-6 py-2.5 bg-[#ff6b00] text-white rounded-xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 flex items-center gap-2"
          >
            <Plus size={16} strokeWidth={3} />
            添加内容
          </button>
        </div>
      </div>

      {/* 内容列表 */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-visible">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">图标</th>
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">标题</th>
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">标识键</th>
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">描述</th>
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">排序</th>
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">状态</th>
              <th className="px-6 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider text-right">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {loading ? (
              <tr><td colSpan={7} className="px-6 py-12 text-center text-gray-400">加载中...</td></tr>
            ) : contents.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center">
                  <div className="flex flex-col items-center gap-3">
                    <BookOpen size={48} className="text-gray-300" />
                    <p className="text-gray-400">暂无帮助内容</p>
                    <button
                      onClick={handleInitDefault}
                      className="text-[#ff6b00] hover:underline text-sm font-medium"
                    >
                      点击初始化默认内容
                    </button>
                  </div>
                </td>
              </tr>
            ) : (
              contents.map((content) => {
                const isOpen = openMenuId === content.id;
                const IconComponent = getIconComponent(content.icon);
                
                return (
                  <tr key={content.id} className="hover:bg-gray-50/50 transition-colors align-top">
                    <td className="px-6 py-4">
                      <div 
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: `${content.icon_color}20` }}
                      >
                        <IconComponent size={20} style={{ color: content.icon_color }} />
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-[#2d3343] font-bold text-sm">{content.title}</span>
                    </td>
                    <td className="px-6 py-4">
                      <code className="px-2 py-1 bg-gray-100 rounded text-xs text-gray-600">{content.key}</code>
                    </td>
                    <td className="px-6 py-4 text-gray-500 text-sm max-w-xs truncate">
                      {content.description || '-'}
                    </td>
                    <td className="px-6 py-4 text-gray-500 text-sm">
                      {content.order}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        content.is_active 
                          ? 'bg-green-100 text-green-600' 
                          : 'bg-gray-100 text-gray-500'
                      }`}>
                        {content.is_active ? '启用' : '禁用'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div 
                        className="relative inline-block" 
                        ref={el => { menuRefs.current[content.id] = el; }}
                      >
                        <button 
                          onClick={() => toggleMenu(content.id)}
                          className="text-gray-400 hover:text-[#ff6b00] transition-colors p-1 rounded hover:bg-gray-100"
                          type="button"
                        >
                          <MoreVertical size={20} />
                        </button>
                        
                        {/* 下拉菜单 */}
                        {isOpen && (
                          <div className={`absolute right-0 w-36 bg-white rounded-lg shadow-lg border border-gray-100 py-1 z-50 ${
                            menuDirection === 'up' ? 'bottom-full mb-1' : 'top-full mt-1'
                          }`}>
                            <button
                              type="button"
                              onClick={() => handleView(content)}
                              className="w-full px-4 py-2.5 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
                            >
                              <Eye size={16} />
                              查看详情
                            </button>
                            <button
                              type="button"
                              onClick={() => handleEdit(content)}
                              className="w-full px-4 py-2.5 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2 transition-colors"
                            >
                              <Edit2 size={16} />
                              编辑
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDelete(content)}
                              className="w-full px-4 py-2.5 text-left text-sm text-red-600 hover:bg-red-50 flex items-center gap-2 transition-colors"
                            >
                              <Trash2 size={16} />
                              删除
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

      {/* 编辑模态框 */}
      <EditModal
        isOpen={isEditModalOpen}
        onClose={() => { setIsEditModalOpen(false); setEditingContent(null); }}
        onSuccess={fetchData}
        editingContent={editingContent}
      />

      {/* 详情查看模态框 */}
      <DetailModal
        isOpen={isDetailModalOpen}
        onClose={() => { setIsDetailModalOpen(false); setViewingContent(null); }}
        content={viewingContent}
      />
    </div>
  );
};

export default HelpContentManage;
