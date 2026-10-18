const form = document.getElementById('change-password-form');
const message = document.getElementById('message');

form.addEventListener('submit', async event => {
    event.preventDefault();
    message.textContent = '';
    message.className = 'message';

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (newPassword !== confirmPassword) {
        message.textContent = 'Les nouveaux mots de passe ne correspondent pas.';
        message.classList.add('error');
        return;
    }

    try {
        const options = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword, newPassword })
        };
        let response = await fetch('/api/auth/change-password', options);

        if (response.status === 401) {
            const refreshResponse = await fetch('/api/auth/refresh', { method: 'POST' });
            if (!refreshResponse.ok) {
                window.location.href = '/login';
                return;
            }

            response = await fetch('/api/auth/change-password', options);
        }

        const result = await response.json();

        if (!response.ok) {
            message.textContent = result.erreur || 'Impossible de modifier le mot de passe.';
            message.classList.add('error');
            return;
        }

        window.location.href = '/bat-computer';
    } catch (error) {
        console.error('Erreur lors du changement de mot de passe :', error);
        message.textContent = 'Une erreur est survenue. Veuillez réessayer.';
        message.classList.add('error');
    }
});
