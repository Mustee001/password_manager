import { useState, useEffect, useCallback } from 'react';
import { Shield, Moon, Sun, LogOut, Menu, X } from 'lucide-react';
import api from './utils/api';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

function App() {
  const [darkMode, setDarkMode] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isInitialized, setIsInitialized] = useState(null);
  const [loading, setLoading] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [lastActivity, setLastActivity] = useState(Date.now());

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
  }, [darkMode]);

  useEffect(() => {
    checkStatus();
    
    const handleSessionExpired = () => {
      setIsAuthenticated(false);
      api.setToken(null);
    };
    
    window.addEventListener('session-expired', handleSessionExpired);
    return () => window.removeEventListener('session-expired', handleSessionExpired);
  }, []);

  useEffect(() => {
    const handleActivity = () => setLastActivity(Date.now());
    
    window.addEventListener('mousemove', handleActivity);
    window.addEventListener('keydown', handleActivity);
    window.addEventListener('click', handleActivity);
    window.addEventListener('touchstart', handleActivity);
    
    return () => {
      window.removeEventListener('mousemove', handleActivity);
      window.removeEventListener('keydown', handleActivity);
      window.removeEventListener('click', handleActivity);
      window.removeEventListener('touchstart', handleActivity);
    };
  }, []);

  useEffect(() => {
    if (!isAuthenticated) return;
    
    const AUTO_LOCK_MS = 5 * 60 * 1000;
    
    const checkInactivity = setInterval(() => {
      if (Date.now() - lastActivity > AUTO_LOCK_MS) {
        handleLogout();
      }
    }, 10000);
    
    return () => clearInterval(checkInactivity);
  }, [isAuthenticated, lastActivity]);

  useEffect(() => {
    if (!isAuthenticated) return;
    
    const refreshInterval = setInterval(async () => {
      try {
        await api.refreshToken();
      } catch (error) {
        console.error('Token refresh failed');
      }
    }, 15 * 60 * 1000);
    
    return () => clearInterval(refreshInterval);
  }, [isAuthenticated]);

  const checkStatus = async () => {
    try {
      const status = await api.getStatus();
      setIsInitialized(status.initialized);
      
      if (api.getToken()) {
        try {
          await api.getPasswords();
          setIsAuthenticated(true);
        } catch {
          api.setToken(null);
          setIsAuthenticated(false);
        }
      }
    } catch (error) {
      console.error('Failed to check status:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAuthSuccess = () => {
    setIsAuthenticated(true);
    setIsInitialized(true);
    setLastActivity(Date.now());
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setIsAuthenticated(false);
      setMobileMenuOpen(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-16 h-16 text-teal-500 mx-auto animate-pulse" />
          <p className="mt-4 text-slate-400 animate-pulse">Loading AegisVault...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen transition-colors duration-300 ${
      darkMode 
        ? 'bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950' 
        : 'bg-gradient-to-br from-slate-100 via-white to-slate-100'
    }`}>
      <header className={`sticky top-0 z-50 backdrop-blur-xl border-b ${
        darkMode ? 'bg-slate-900/80 border-slate-800' : 'bg-white/80 border-slate-200'
      }`}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="w-8 h-8 text-teal-500" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-amber-500 rounded-full animate-pulse" />
              </div>
              <div>
                <h1 className={`text-xl font-bold ${darkMode ? 'text-white' : 'text-slate-900'}`}>
                  Aegis<span className="text-teal-500">Vault</span>
                </h1>
                <p className={`text-xs ${darkMode ? 'text-slate-500' : 'text-slate-400'}`}>
                  Elite Password Security
                </p>
              </div>
            </div>

            <div className="hidden md:flex items-center gap-4">
              <button
                onClick={() => setDarkMode(!darkMode)}
                className={`p-2 rounded-lg transition-colors ${
                  darkMode 
                    ? 'hover:bg-slate-800 text-slate-400 hover:text-white' 
                    : 'hover:bg-slate-100 text-slate-600 hover:text-slate-900'
                }`}
              >
                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
              </button>
              
              {isAuthenticated && (
                <button
                  onClick={handleLogout}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                    darkMode 
                      ? 'hover:bg-slate-800 text-slate-400 hover:text-white' 
                      : 'hover:bg-slate-100 text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <LogOut className="w-4 h-4" />
                  <span>Lock Vault</span>
                </button>
              )}
            </div>

            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className={`md:hidden p-2 rounded-lg ${
                darkMode ? 'text-slate-400 hover:bg-slate-800' : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>

        {mobileMenuOpen && (
          <div className={`md:hidden border-t ${
            darkMode ? 'bg-slate-900/95 border-slate-800' : 'bg-white/95 border-slate-200'
          }`}>
            <div className="px-4 py-4 space-y-2">
              <button
                onClick={() => { setDarkMode(!darkMode); setMobileMenuOpen(false); }}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg ${
                  darkMode 
                    ? 'hover:bg-slate-800 text-slate-300' 
                    : 'hover:bg-slate-100 text-slate-700'
                }`}
              >
                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                <span>{darkMode ? 'Light Mode' : 'Dark Mode'}</span>
              </button>
              
              {isAuthenticated && (
                <button
                  onClick={handleLogout}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg ${
                    darkMode 
                      ? 'hover:bg-slate-800 text-slate-300' 
                      : 'hover:bg-slate-100 text-slate-700'
                  }`}
                >
                  <LogOut className="w-5 h-5" />
                  <span>Lock Vault</span>
                </button>
              )}
            </div>
          </div>
        )}
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {isAuthenticated ? (
          <Dashboard darkMode={darkMode} />
        ) : (
          <Login 
            isSetup={!isInitialized} 
            onSuccess={handleAuthSuccess}
            darkMode={darkMode}
          />
        )}
      </main>

      <footer className={`mt-auto py-6 border-t ${
        darkMode ? 'border-slate-800' : 'border-slate-200'
      }`}>
        <div className="max-w-7xl mx-auto px-4 text-center">
          <p className={`text-sm ${darkMode ? 'text-slate-500' : 'text-slate-400'}`}>
            AegisVault v2.0 - Your passwords, encrypted and secure.
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
