import { useState, useEffect } from 'react';
import { 
  Plus, Search, Key, Globe, User, Eye, EyeOff, Copy, Edit2, Trash2, 
  RefreshCw, Download, Upload, X, Check, Sparkles, AlertCircle, Shuffle
} from 'lucide-react';
import api from '../utils/api';

function Dashboard({ darkMode }) {
  const [passwords, setPasswords] = useState([]);
  const [filteredPasswords, setFilteredPasswords] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(null);
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [visiblePasswords, setVisiblePasswords] = useState({});
  const [copiedField, setCopiedField] = useState(null);
  const [notification, setNotification] = useState(null);

  useEffect(() => {
    loadPasswords();
  }, []);

  useEffect(() => {
    if (searchQuery) {
      const filtered = passwords.filter(p => 
        p.website.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.username.toLowerCase().includes(searchQuery.toLowerCase())
      );
      setFilteredPasswords(filtered);
    } else {
      setFilteredPasswords(passwords);
    }
  }, [searchQuery, passwords]);

  const loadPasswords = async () => {
    try {
      const data = await api.getPasswords();
      setPasswords(data.passwords);
    } catch (error) {
      showNotification('Failed to load passwords', 'error');
    } finally {
      setLoading(false);
    }
  };

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
  };

  const copyToClipboard = async (text, field) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
      showNotification('Copied! Will clear in 30s', 'success');
      setTimeout(() => navigator.clipboard.writeText(''), 30000);
    } catch (error) {
      showNotification('Failed to copy', 'error');
    }
  };

  const togglePasswordVisibility = (id) => {
    setVisiblePasswords(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleDelete = async (website) => {
    if (!confirm(`Delete password for ${website}?`)) return;
    try {
      await api.deletePassword(website);
      await loadPasswords();
      showNotification('Password deleted');
    } catch (error) {
      showNotification(error.message, 'error');
    }
  };

  const handleExport = async () => {
    try {
      const data = await api.exportPasswords();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegisvault-export-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Passwords exported');
    } catch (error) {
      showNotification('Export failed', 'error');
    }
  };

  const handleImport = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      const passwords = data.passwords || data;
      const result = await api.importPasswords(passwords);
      await loadPasswords();
      showNotification(`Imported ${result.imported} passwords (${result.skipped} skipped)`);
    } catch (error) {
      showNotification('Import failed: ' + error.message, 'error');
    }
    e.target.value = '';
  };

  return (
    <div className="space-y-6 fade-in">
      {notification && (
        <div className={`fixed top-20 right-4 z-50 px-6 py-3 rounded-lg shadow-lg flex items-center gap-2 slide-in ${
          notification.type === 'error' 
            ? 'bg-red-500 text-white' 
            : 'bg-teal-500 text-white'
        }`}>
          {notification.type === 'error' ? <AlertCircle className="w-5 h-5" /> : <Check className="w-5 h-5" />}
          {notification.message}
        </div>
      )}

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>
            Password Vault
          </h2>
          <p className={`${darkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            {passwords.length} passwords stored securely
          </p>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setShowModal('generate')}
            className="btn-primary flex items-center gap-2"
          >
            <Sparkles className="w-4 h-4" />
            Generate
          </button>
          <button
            onClick={() => { setSelectedEntry(null); setShowModal('add'); }}
            className="btn-secondary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add New
          </button>
          <button
            onClick={handleExport}
            className={`p-2.5 rounded-lg border transition-colors ${
              darkMode 
                ? 'border-slate-700 hover:bg-slate-800 text-slate-400' 
                : 'border-slate-300 hover:bg-slate-100 text-slate-600'
            }`}
            title="Export"
          >
            <Download className="w-5 h-5" />
          </button>
          <label className={`p-2.5 rounded-lg border cursor-pointer transition-colors ${
            darkMode 
              ? 'border-slate-700 hover:bg-slate-800 text-slate-400' 
              : 'border-slate-300 hover:bg-slate-100 text-slate-600'
          }`} title="Import">
            <Upload className="w-5 h-5" />
            <input type="file" accept=".json,.csv" onChange={handleImport} className="hidden" />
          </label>
        </div>
      </div>

      <div className="relative">
        <Search className={`absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 ${
          darkMode ? 'text-slate-500' : 'text-slate-400'
        }`} />
        <input
          type="text"
          placeholder="Search passwords..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className={`w-full pl-12 pr-4 py-3 rounded-xl border transition-all ${
            darkMode 
              ? 'bg-slate-800/50 border-slate-700 text-white placeholder-slate-500 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20' 
              : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'
          }`}
        />
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <RefreshCw className="w-8 h-8 text-teal-500 animate-spin" />
        </div>
      ) : filteredPasswords.length === 0 ? (
        <div className={`text-center py-20 ${
          darkMode ? 'card' : 'bg-white border border-slate-200 rounded-xl shadow-lg'
        } p-8`}>
          <Key className={`w-16 h-16 mx-auto mb-4 ${darkMode ? 'text-slate-600' : 'text-slate-400'}`} />
          <h3 className={`text-xl font-semibold mb-2 ${darkMode ? 'text-white' : 'text-slate-900'}`}>
            {searchQuery ? 'No matches found' : 'No passwords yet'}
          </h3>
          <p className={`${darkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            {searchQuery 
              ? 'Try a different search term' 
              : 'Add your first password to get started'}
          </p>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredPasswords.map((entry) => (
            <div
              key={entry.id}
              className={`group p-5 rounded-xl border transition-all hover:shadow-lg ${
                darkMode 
                  ? 'bg-slate-800/50 border-slate-700/50 hover:border-teal-500/30' 
                  : 'bg-white border-slate-200 hover:border-teal-500/30 shadow-sm'
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    darkMode ? 'bg-teal-500/10' : 'bg-teal-50'
                  }`}>
                    <Globe className="w-5 h-5 text-teal-500" />
                  </div>
                  <div>
                    <h3 className={`font-semibold ${darkMode ? 'text-white' : 'text-slate-900'}`}>
                      {entry.website}
                    </h3>
                    <p className={`text-sm ${darkMode ? 'text-slate-400' : 'text-slate-500'}`}>
                      {entry.username}
                    </p>
                  </div>
                </div>
                
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => { setSelectedEntry(entry); setShowModal('edit'); }}
                    className={`p-1.5 rounded-lg transition-colors ${
                      darkMode ? 'hover:bg-slate-700 text-slate-400' : 'hover:bg-slate-100 text-slate-500'
                    }`}
                  >
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(entry.website)}
                    className={`p-1.5 rounded-lg transition-colors ${
                      darkMode ? 'hover:bg-red-500/10 text-red-400' : 'hover:bg-red-50 text-red-500'
                    }`}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className={`flex items-center gap-2 p-3 rounded-lg ${
                darkMode ? 'bg-slate-900/50' : 'bg-slate-50'
              }`}>
                <Key className={`w-4 h-4 ${darkMode ? 'text-slate-500' : 'text-slate-400'}`} />
                <span className={`flex-1 font-mono text-sm ${
                  darkMode ? 'text-slate-300' : 'text-slate-700'
                }`}>
                  {visiblePasswords[entry.id] ? entry.password : '••••••••••••'}
                </span>
                <button
                  onClick={() => togglePasswordVisibility(entry.id)}
                  className={`p-1 rounded ${
                    darkMode ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-200 text-slate-500'
                  }`}
                >
                  {visiblePasswords[entry.id] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => copyToClipboard(entry.password, entry.id)}
                  className={`p-1 rounded ${
                    copiedField === entry.id 
                      ? 'text-teal-500' 
                      : darkMode ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-200 text-slate-500'
                  }`}
                >
                  {copiedField === entry.id ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>

              {entry.notes && (
                <p className={`mt-3 text-sm ${darkMode ? 'text-slate-500' : 'text-slate-400'}`}>
                  {entry.notes}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <Modal 
          type={showModal}
          entry={selectedEntry}
          darkMode={darkMode}
          onClose={() => { setShowModal(null); setSelectedEntry(null); }}
          onSave={async (data) => {
            try {
              if (showModal === 'add') {
                await api.addPassword(data);
                showNotification('Password saved');
              } else if (showModal === 'edit') {
                await api.updatePassword(selectedEntry.website, data);
                showNotification('Password updated');
              }
              await loadPasswords();
              setShowModal(null);
              setSelectedEntry(null);
            } catch (error) {
              showNotification(error.message, 'error');
            }
          }}
        />
      )}
    </div>
  );
}

function Modal({ type, entry, darkMode, onClose, onSave }) {
  const [formData, setFormData] = useState({
    website: entry?.website || '',
    username: entry?.username || '',
    password: entry?.password || '',
    notes: entry?.notes || ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genOptions, setGenOptions] = useState({
    length: 16,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    mode: 'random',
    phrase: '',
    style: 'intact'
  });
  const [strength, setStrength] = useState(null);

  const generatePassword = async () => {
    setGenerating(true);
    try {
      const options = genOptions.mode === 'random' 
        ? {
            mode: 'random',
            length: genOptions.length,
            uppercase: genOptions.uppercase,
            lowercase: genOptions.lowercase,
            digits: genOptions.digits,
            symbols: genOptions.symbols
          }
        : {
            mode: 'custom',
            phrase: genOptions.phrase,
            style: genOptions.style
          };
      
      const result = await api.generatePassword(options);
      setFormData(prev => ({ ...prev, password: result.password }));
      setStrength(result.strength);
    } catch (error) {
      console.error('Generation failed:', error);
    } finally {
      setGenerating(false);
    }
  };

  const checkPasswordStrength = async (pwd) => {
    if (pwd.length > 0) {
      try {
        const result = await api.checkStrength(pwd);
        setStrength(result);
      } catch {
        setStrength(null);
      }
    }
  };

  const isGenerator = type === 'generate';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
      <div className={`w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl shadow-2xl ${
        darkMode ? 'bg-slate-900 border border-slate-800' : 'bg-white'
      } fade-in`}>
        <div className={`sticky top-0 flex items-center justify-between p-6 border-b ${
          darkMode ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'
        }`}>
          <h3 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>
            {isGenerator ? 'Generate Password' : type === 'add' ? 'Add Password' : 'Edit Password'}
          </h3>
          <button
            onClick={onClose}
            className={`p-2 rounded-lg ${
              darkMode ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-100 text-slate-500'
            }`}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          {isGenerator && (
            <>
              <div className="flex gap-2 p-1 rounded-lg bg-slate-800/50">
                <button
                  onClick={() => setGenOptions(prev => ({ ...prev, mode: 'random' }))}
                  className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                    genOptions.mode === 'random'
                      ? 'bg-teal-500 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Random
                </button>
                <button
                  onClick={() => setGenOptions(prev => ({ ...prev, mode: 'custom' }))}
                  className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                    genOptions.mode === 'custom'
                      ? 'bg-teal-500 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Custom Phrase
                </button>
              </div>

              {genOptions.mode === 'random' ? (
                <>
                  <div>
                    <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
                      Length: {genOptions.length}
                    </label>
                    <input
                      type="range"
                      min="8"
                      max="64"
                      value={genOptions.length}
                      onChange={(e) => setGenOptions(prev => ({ ...prev, length: parseInt(e.target.value) }))}
                      className="w-full accent-teal-500"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { key: 'uppercase', label: 'Uppercase (A-Z)' },
                      { key: 'lowercase', label: 'Lowercase (a-z)' },
                      { key: 'digits', label: 'Numbers (0-9)' },
                      { key: 'symbols', label: 'Symbols (!@#)' }
                    ].map(({ key, label }) => (
                      <label key={key} className={`flex items-center gap-2 p-3 rounded-lg cursor-pointer ${
                        darkMode ? 'bg-slate-800/50 hover:bg-slate-800' : 'bg-slate-50 hover:bg-slate-100'
                      }`}>
                        <input
                          type="checkbox"
                          checked={genOptions[key]}
                          onChange={(e) => setGenOptions(prev => ({ ...prev, [key]: e.target.checked }))}
                          className="w-4 h-4 text-teal-500 rounded border-slate-500 focus:ring-teal-500"
                        />
                        <span className={`text-sm ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>{label}</span>
                      </label>
                    ))}
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
                      Memorable Phrase (4-12 characters)
                    </label>
                    <input
                      type="text"
                      value={genOptions.phrase}
                      onChange={(e) => setGenOptions(prev => ({ ...prev, phrase: e.target.value }))}
                      placeholder="e.g., sunshine, coffee"
                      className={`w-full px-4 py-3 rounded-lg border ${
                        darkMode 
                          ? 'bg-slate-800/50 border-slate-700 text-white' 
                          : 'bg-white border-slate-300 text-slate-900'
                      }`}
                    />
                  </div>
                  <div>
                    <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
                      Style
                    </label>
                    <select
                      value={genOptions.style}
                      onChange={(e) => setGenOptions(prev => ({ ...prev, style: e.target.value }))}
                      className={`w-full px-4 py-3 rounded-lg border ${
                        darkMode 
                          ? 'bg-slate-800/50 border-slate-700 text-white' 
                          : 'bg-white border-slate-300 text-slate-900'
                      }`}
                    >
                      <option value="intact">Keep phrase intact</option>
                      <option value="2">Split into 2-char chunks</option>
                      <option value="3">Split into 3-char chunks</option>
                    </select>
                  </div>
                </>
              )}

              <button
                onClick={generatePassword}
                disabled={generating || (genOptions.mode === 'custom' && (genOptions.phrase.length < 4 || genOptions.phrase.length > 12))}
                className="w-full btn-primary flex items-center justify-center gap-2"
              >
                {generating ? (
                  <RefreshCw className="w-5 h-5 animate-spin" />
                ) : (
                  <>
                    <Shuffle className="w-5 h-5" />
                    Generate Password
                  </>
                )}
              </button>
            </>
          )}

          {!isGenerator && (
            <>
              <div>
                <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
                  <Globe className="w-4 h-4 inline mr-2" />
                  Website/Service
                </label>
                <input
                  type="text"
                  value={formData.website}
                  onChange={(e) => setFormData(prev => ({ ...prev, website: e.target.value }))}
                  placeholder="e.g., github.com"
                  className={`w-full px-4 py-3 rounded-lg border ${
                    darkMode 
                      ? 'bg-slate-800/50 border-slate-700 text-white' 
                      : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>

              <div>
                <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
                  <User className="w-4 h-4 inline mr-2" />
                  Username/Email
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                  placeholder="e.g., user@email.com"
                  className={`w-full px-4 py-3 rounded-lg border ${
                    darkMode 
                      ? 'bg-slate-800/50 border-slate-700 text-white' 
                      : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
            </>
          )}

          <div>
            <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
              <Key className="w-4 h-4 inline mr-2" />
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={formData.password}
                onChange={(e) => {
                  setFormData(prev => ({ ...prev, password: e.target.value }));
                  checkPasswordStrength(e.target.value);
                }}
                placeholder="Enter or generate password"
                className={`w-full px-4 py-3 pr-24 rounded-lg border font-mono ${
                  darkMode 
                    ? 'bg-slate-800/50 border-slate-700 text-white' 
                    : 'bg-white border-slate-300 text-slate-900'
                }`}
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className={`p-2 rounded ${darkMode ? 'hover:bg-slate-700 text-slate-400' : 'hover:bg-slate-100 text-slate-500'}`}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                {!isGenerator && (
                  <button
                    type="button"
                    onClick={async () => {
                      const result = await api.generatePassword({ mode: 'random', length: 16, uppercase: true, lowercase: true, digits: true, symbols: true });
                      setFormData(prev => ({ ...prev, password: result.password }));
                      setStrength(result.strength);
                    }}
                    className={`p-2 rounded ${darkMode ? 'hover:bg-slate-700 text-teal-400' : 'hover:bg-slate-100 text-teal-500'}`}
                    title="Generate"
                  >
                    <Sparkles className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            {strength && formData.password && (
              <div className="mt-2">
                <div className="flex justify-between text-sm mb-1">
                  <span className={darkMode ? 'text-slate-400' : 'text-slate-500'}>Strength</span>
                  <span className={`font-medium ${
                    strength.strength === 'excellent' ? 'text-teal-500' :
                    strength.strength === 'strong' ? 'text-green-500' :
                    strength.strength === 'good' ? 'text-yellow-500' :
                    'text-red-500'
                  }`}>
                    {strength.label}
                  </span>
                </div>
                <div className={`h-1.5 rounded-full overflow-hidden ${darkMode ? 'bg-slate-700' : 'bg-slate-200'}`}>
                  <div 
                    className={`h-full transition-all ${
                      strength.strength === 'excellent' ? 'bg-teal-500' :
                      strength.strength === 'strong' ? 'bg-green-500' :
                      strength.strength === 'good' ? 'bg-yellow-500' :
                      'bg-red-500'
                    }`}
                    style={{ width: `${strength.percentage}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {!isGenerator && (
            <div>
              <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-slate-300' : 'text-slate-700'}`}>
                Notes (optional)
              </label>
              <textarea
                value={formData.notes}
                onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))}
                placeholder="Add any notes..."
                rows={3}
                className={`w-full px-4 py-3 rounded-lg border resize-none ${
                  darkMode 
                    ? 'bg-slate-800/50 border-slate-700 text-white' 
                    : 'bg-white border-slate-300 text-slate-900'
                }`}
              />
            </div>
          )}
        </div>

        <div className={`sticky bottom-0 flex gap-3 p-6 border-t ${
          darkMode ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'
        }`}>
          <button onClick={onClose} className="flex-1 btn-secondary">
            Cancel
          </button>
          {!isGenerator && (
            <button
              onClick={() => onSave(formData)}
              disabled={!formData.website || !formData.username || !formData.password}
              className="flex-1 btn-primary"
            >
              {type === 'add' ? 'Save Password' : 'Update'}
            </button>
          )}
          {isGenerator && formData.password && (
            <button
              onClick={() => {
                navigator.clipboard.writeText(formData.password);
                setTimeout(() => navigator.clipboard.writeText(''), 30000);
              }}
              className="flex-1 btn-primary flex items-center justify-center gap-2"
            >
              <Copy className="w-4 h-4" />
              Copy Password
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
