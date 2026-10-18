async function fetchWithRetry(url, options = {}) {
  let response = await fetch(url, options);

  if (response.status === 401) {
    console.warn("JWT expiré. Tentative de rafraîchissement automatique...");
    const refreshResponse = await fetch('/api/auth/refresh', { method: 'POST' });
    
    if (refreshResponse.ok) {
      console.log("Nouveau JWT obtenu ! Rejeu de la requête initiale.");
      response = await fetch(url, options);
    } else {
      console.error("Le Refresh Token est également invalide ou révoqué.");
      window.location.href = '/login';
      return null;
    }
  }
  return response;
}

async function loadDashboard() {
  const welcome = document.querySelector('.hello');
  const gadgetsContainer = document.querySelector('.gadgets');

  try {
    const userResponse = await fetchWithRetry('/api/me');
    if (!userResponse) return;

    if (userResponse.ok) {
      const user = await userResponse.json();
      welcome.textContent = `🦇 Bienvenue, ${user.username}`;
    } else {
      welcome.textContent = '🦇 Erreur - Authentification requise';
      return;
    }

    const gadgetsResponse = await fetchWithRetry('/api/secrets');
    if (!gadgetsResponse) return;

    if (gadgetsResponse.ok) {
      const { gadgets } = await gadgetsResponse.json();
      gadgetsContainer.innerHTML = gadgets.map(gadget => `
        <div class="col-md-6 col-lg-4">
          <div class="gadget-card p-4">
            <div class="text-center">
              <i class="fas ${gadget.icon} gadget-icon"></i>
              <h3 class="gadget-name">${gadget.name}</h3>
              <p class="gadget-desc">${gadget.desc}</p>
            </div>
          </div>
        </div>
      `).join('');
    } else {
      gadgetsContainer.innerHTML = '<div class="col-12"><p class="text-danger">Erreur lors de la récupération des gadgets</p></div>';
    }
  } catch (error) {
    console.error('Erreur de chargement du tableau de bord :', error);
    gadgetsContainer.innerHTML = '<div class="col-12"><p class="text-danger">Erreur de chargement</p></div>';
  }
}

document.querySelector('.logout-btn').addEventListener('click', async () => {
  try {
    const response = await fetch('/logout', { method: 'POST' });
    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.erreur || 'La déconnexion a échoué.');
    }

    window.location.href = result.redirect || '/login';
  } catch (error) {
    console.error('Erreur logout:', error);
    window.alert('Impossible de terminer la déconnexion. Veuillez réessayer.');
  }
});

loadDashboard();