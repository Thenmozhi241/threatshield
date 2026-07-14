// Theme toggle: persists the user's light/dark preference in localStorage.
// This is a real deployed web app (not a Claude artifact sandbox), so
// localStorage is the correct, standard tool here.
(function () {
    const root = document.documentElement;
    const stored = localStorage.getItem('threatshield-theme');
    if (stored) root.setAttribute('data-theme', stored);

    document.addEventListener('DOMContentLoaded', () => {
        const toggle = document.getElementById('themeToggle');
        if (!toggle) return;
        toggle.addEventListener('click', () => {
            const current = root.getAttribute('data-theme') || 'light';
            const next = current === 'light' ? 'dark' : 'light';
            root.setAttribute('data-theme', next);
            localStorage.setItem('threatshield-theme', next);
        });

        document.querySelectorAll('form[data-confirm]').forEach((form) => {
            form.addEventListener('submit', (event) => {
                const message = form.getAttribute('data-confirm') || 'Are you sure?';
                if (!window.confirm(message)) event.preventDefault();
            });
        });

        // Tab switching for asset detail / tool pages
        document.querySelectorAll('.tabs').forEach((tabGroup) => {
            const links = tabGroup.querySelectorAll('.tab-link');
            links.forEach((link) => {
                link.addEventListener('click', (event) => {
                    event.preventDefault();
                    const targetId = link.getAttribute('data-target');
                    links.forEach((l) => l.classList.remove('active'));
                    link.classList.add('active');
                    const panelContainer = document.querySelector(link.getAttribute('data-panel-container') || '[data-tab-panels]');
                    if (panelContainer) {
                        panelContainer.querySelectorAll('.tab-panel').forEach((panel) => {
                            panel.classList.toggle('active', panel.id === targetId);
                        });
                    }
                });
            });
        });
    });
})();
