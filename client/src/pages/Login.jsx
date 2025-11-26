import { useState } from 'react';
import { Shield, Eye, EyeOff, Lock, AlertCircle, CheckCircle } from 'lucide-react';
import api from '../utils/api';

function Login({ isSetup, onSuccess, darkMode }) {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [strength, setStrength] = useState(null);

  const checkStrength = async (pwd) => {
    if (pwd.length > 0) {
      try {
        const result = await api.checkStrength(pwd);
        setStrength(result);
      } catch {
        setStrength(null);
      }
    } else {
      setStrength(null);
    }
  };

  const handlePasswordChange = (e) => {
    const value = e.target.value;
    setPassword(value);
    if (isSetup) {
      checkStrength(value);
    }
  };

  const getStrengthColor = () => {
    if (!strength) return 'bg-slate-600';
    switch (strength.strength) {
      case 'excellent': return 'bg-teal-500';
      case 'strong': return 'bg-green-500';
      case 'good': return 'bg-yellow-500';
      case 'weak': return 'bg-red-500';
      default: return 'bg-slate-600';
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isSetup) {
        if (password !== confirmPassword) {
          setError('Passwords do not match');
          setLoading(false);
          return;
        }
        if (strength?.strength === 'weak') {
          setError('Please choose a stronger password');
          setLoading(false);
          return;
        }
        await api.setup(password);
      } else {
        await api.login(password);
      }
      onSuccess();
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[70vh] flex items-center justify-center py-12 px-4">
      <div className={`w-full max-w-md ${
        darkMode ? 'glass-card' : 'bg-white shadow-xl border border-slate-200 rounded-2xl'
      } p-8 fade-in`}>
        <div className="text-center mb-8">
          <div className="relative inline-block mb-6">
            <div className={`absolute inset-0 ${
              darkMode ? 'bg-teal-500/20' : 'bg-teal-500/10'
            } rounded-full blur-xl animate-pulse-slow`} />
            <Shield className="relative w-20 h-20 text-teal-500 mx-auto" />
          </div>
          
          <h2 className={`text-2xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-slate-900'}`}>
            {isSetup ? 'Create Your Vault' : 'Unlock Your Vault'}
          </h2>
          <p className={`${darkMode ? 'text-slate-400' : 'text-slate-500'}`}>
            {isSetup 
              ? 'Set a strong master password to protect your vault' 
              : 'Enter your master password to access your passwords'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className={`block text-sm font-medium mb-2 ${
              darkMode ? 'text-slate-300' : 'text-slate-700'
            }`}>
              <Lock className="w-4 h-4 inline mr-2" />
              Master Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={handlePasswordChange}
                className={`w-full px-4 py-3 pr-12 rounded-lg border transition-all ${
                  darkMode 
                    ? 'bg-slate-800/50 border-slate-700 text-white placeholder-slate-500 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20' 
                    : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'
                }`}
                placeholder="Enter master password"
                required
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className={`absolute right-3 top-1/2 -translate-y-1/2 ${
                  darkMode ? 'text-slate-400 hover:text-white' : 'text-slate-400 hover:text-slate-600'
                }`}
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>

            {isSetup && password && strength && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className={darkMode ? 'text-slate-400' : 'text-slate-500'}>
                    Strength
                  </span>
                  <span className={`font-medium ${
                    strength.strength === 'excellent' ? 'text-teal-500' :
                    strength.strength === 'strong' ? 'text-green-500' :
                    strength.strength === 'good' ? 'text-yellow-500' :
                    'text-red-500'
                  }`}>
                    {strength.label}
                  </span>
                </div>
                <div className={`h-2 rounded-full overflow-hidden ${
                  darkMode ? 'bg-slate-700' : 'bg-slate-200'
                }`}>
                  <div 
                    className={`h-full transition-all duration-300 ${getStrengthColor()}`}
                    style={{ width: `${strength.percentage}%` }}
                  />
                </div>
                {strength.feedback && strength.feedback.length > 0 && (
                  <ul className="text-xs space-y-1">
                    {strength.feedback.map((tip, i) => (
                      <li key={i} className={`flex items-center gap-1 ${
                        darkMode ? 'text-slate-400' : 'text-slate-500'
                      }`}>
                        <AlertCircle className="w-3 h-3" />
                        {tip}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

          {isSetup && (
            <div>
              <label className={`block text-sm font-medium mb-2 ${
                darkMode ? 'text-slate-300' : 'text-slate-700'
              }`}>
                <CheckCircle className="w-4 h-4 inline mr-2" />
                Confirm Password
              </label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className={`w-full px-4 py-3 rounded-lg border transition-all ${
                  darkMode 
                    ? 'bg-slate-800/50 border-slate-700 text-white placeholder-slate-500 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20' 
                    : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400 focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20'
                }`}
                placeholder="Confirm your password"
                required
              />
              {confirmPassword && password !== confirmPassword && (
                <p className="mt-2 text-sm text-red-500 flex items-center gap-1">
                  <AlertCircle className="w-4 h-4" />
                  Passwords do not match
                </p>
              )}
            </div>
          )}

          {error && (
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
              <p className="text-red-500 text-sm">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || (isSetup && password !== confirmPassword)}
            className="w-full btn-primary py-3 text-lg font-semibold"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                {isSetup ? 'Creating Vault...' : 'Unlocking...'}
              </span>
            ) : (
              isSetup ? 'Create Vault' : 'Unlock Vault'
            )}
          </button>
        </form>

        {isSetup && (
          <div className={`mt-6 p-4 rounded-lg ${
            darkMode ? 'bg-amber-500/10 border border-amber-500/20' : 'bg-amber-50 border border-amber-200'
          }`}>
            <p className={`text-sm ${darkMode ? 'text-amber-400' : 'text-amber-700'}`}>
              <strong>Important:</strong> Your master password cannot be recovered. 
              Make sure to remember it or store it safely.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Login;
