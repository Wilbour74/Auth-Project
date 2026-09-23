window.onload = async function () {
  const fetchUserInfo = async () => {
    try {
      const response = await fetch('/api/me', {
        method: 'GET',
      });
      const h1 = document.querySelector('.hello');
      if (response.ok) {
        const data = await response.json();
        h1.textContent = `🦇 Bienvenue, ${data.username}`;
      } else {
        h1.textContent = '🦇 Erreur - Authentification requise';
      }
    } catch (error) {
      console.error('Erreur:', error);
      h1.textContent = '🦇 Erreur de connexion';
    }
  };

  const fetchGadgets = async () => {
    try {
      const response = await fetch('/api/secrets', {
        method: 'GET',
      });
      const gadgetsContainer = document.querySelector('.gadgets');
      if (response.ok) {
        const data = await response.json();
        gadgetsContainer.innerHTML = data.gadgets.map(gadget => `
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
      console.error('Erreur:', error);
      document.querySelector('.gadgets').innerHTML = '<div class="col-12"><p class="text-danger">Erreur de chargement</p></div>';
    }
  };

  await fetchUserInfo();
  await fetchGadgets();
}