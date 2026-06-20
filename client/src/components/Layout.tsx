import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { useState, useEffect } from "react";
import { useI18n } from "../lib/i18n";

export function Layout() {
    const { t } = useI18n();
    const [theme, setTheme] = useState<'light' | 'dark' | 'darker'>(() => {
        if (typeof window !== 'undefined') {
            const savedTheme = localStorage.getItem("theme");
            if (savedTheme === 'light' || savedTheme === 'dark' || savedTheme === 'darker') {
                return savedTheme;
            }
            if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
                return "dark";
            }
        }
        return "light";
    });
    const [isMenuOpen, setIsMenuOpen] = useState(() => {
        if (typeof window !== 'undefined') {
            const saved = localStorage.getItem("menuOpen");
            if (saved !== null) {
                return saved === "true";
            }
            return window.innerWidth >= 1024;
        }
        return true;
    });

    useEffect(() => {
        const root = document.documentElement;
        // 'darker' keeps the 'dark' class (so all dark: utilities still apply) and
        // adds 'theme-darker', which overrides the gray palette to near-black in CSS.
        root.classList.toggle("dark", theme === "dark" || theme === "darker");
        root.classList.toggle("theme-darker", theme === "darker");
        localStorage.setItem("theme", theme);
    }, [theme]);

    useEffect(() => {
        localStorage.setItem("menuOpen", String(isMenuOpen));
    }, [isMenuOpen]);

    const toggleTheme = () => {
        // Cycle: light -> dark -> darker -> light
        setTheme(theme === "light" ? "dark" : theme === "dark" ? "darker" : "light");
    };

    const toggleMenu = () => {
        setIsMenuOpen(!isMenuOpen);
    };

    const location = useLocation();
    
    const getPageTitle = (): string => {
        if (location.pathname.startsWith('/ip/')) {
            return t('pages.ipInvestigation.title');
        }
        switch (location.pathname) {
            case '/':
                return t('pages.dashboard.title');
            case '/incidents':
                return t('pages.incidents.title');
            case '/alerts':
                return t('pages.alerts.title');
            case '/decisions':
                return t('pages.decisions.title');
            case '/self-protection':
                return t('pages.selfProtection.title');
            case '/notifications':
                return t('pages.notifications.title');
            case '/audit-log':
                return t('pages.auditLog.title');
            default:
                return t('pages.dashboard.title');
        }
    };

    return (
        <div className="flex h-[100dvh] bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 font-sans">
            {/* Mobile Sidebar Overlay */}
            <div
                className={`fixed inset-0 bg-black/50 z-40 lg:hidden transition-opacity duration-300 ease-in-out ${isMenuOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'}`}
                onClick={() => setIsMenuOpen(false)}
            />

            <Sidebar
                isOpen={isMenuOpen}
                onClose={() => setIsMenuOpen(false)}
                onToggle={toggleMenu}
                theme={theme}
                toggleTheme={toggleTheme}
            />

            <main className={`flex-1 relative w-full z-0 isolate overflow-auto transition-[padding] duration-300 ease-in-out ${isMenuOpen ? 'lg:pl-[340px]' : 'lg:pl-16'} ${isMenuOpen ? 'lg:overflow-auto overflow-hidden touch-none lg:touch-auto' : ''}`}>
                <div className="sticky top-0 z-30 bg-gray-50 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
                    <div className="container mx-auto px-4 lg:px-8 max-w-[1920px]">
                        <div className="flex items-center gap-4 h-16">
                            {/* Mobile hamburger button */}
                            <button
                                onClick={toggleMenu}
                                className="lg:hidden p-2 rounded-lg bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 shadow-sm transition-colors border border-gray-200 dark:border-gray-700"
                                aria-label={t('components.layout.openMenu')}
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="4" x2="20" y1="12" y2="12" /><line x1="4" x2="20" y1="6" y2="6" /><line x1="4" x2="20" y1="18" y2="18" /></svg>
                            </button>
                            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                                {getPageTitle()}
                            </h1>
                        </div>
                    </div>
                </div>
                
                <div className="container mx-auto p-4 lg:p-8 max-w-[1920px]">
                    <Outlet />
                </div>
            </main>
        </div>
    );
}
