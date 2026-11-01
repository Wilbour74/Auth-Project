async function login () {
  currentUsername = document.getElementById('username').value
  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: currentUsername,
      password: document.getElementById('password').value
    })
  })
  const data = await res.json()

  if (data.requires2FASetup) {
    document.getElementById('two-factor-setup').hidden = false
    document.getElementById('message').textContent = data.error
    document.getElementById('message').className = 'message error'
  } else if (data.requires2FA) {
    document.getElementById('zone2FA').hidden = false
    document.getElementById('message').textContent = ''
  } else if (data.success) {
    window.location.href = '/bat-computer'
  } else {
    document.getElementById('message').textContent = data.error || 'Une erreur est survenue.'
    document.getElementById('message').className = 'message error'
  }
}

let currentUsername = '';

async function chargeQR () {
  currentUsername = document.getElementById('username').value
  const res = await fetch('/setup-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: currentUsername })
  })
  const data = await res.json();

  if (data.error) {
    alert(data.error);
    return;
  }

  if (data.qrCode) {
    document.getElementById('qrZone').innerHTML = `
                    <img src="${data.qrCode}" alt="QR code de configuration 2FA">
                    <label class="form-label" for="confirmCode">Code de vérification</label>
                    <input type="text" id="confirmCode" class="form-control" placeholder="000000" maxlength="6">
                    <button id="confirm-2fa-button" class="btn btn-login" type="button">Confirmer l'activation</button>
                `
    document.getElementById('confirm-2fa-button').addEventListener('click', confirm2FAActivation)
  }
}

async function confirm2FAActivation () {
  const res = await fetch('/confirm-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: currentUsername,
      code: document.getElementById('confirmCode').value
    })
  })
  const data = await res.json()
  document.getElementById('message').textContent = data.message || data.error
  document.getElementById('message').className = `message ${data.success ? 'success' : 'error'}`
  if (data.success) {
    document.getElementById('two-factor-setup').hidden = true
  }
}

async function valid2FAConnection2FA () {
  const code = document.getElementById('code2FA').value.trim()
  if (!/^\d{6}$/.test(code)) {
    alert('Saisissez un code valide de 6 chiffres.')
    return
  }

  const res = await fetch('/verify-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: currentUsername,
      code
    })
  })
  const data = await res.json()

  if (data.success) {
    window.location.href = '/bat-computer'
  } else {
    alert(data.error || 'Code de vérification invalide.')
  }
}

document.getElementById('login-button').addEventListener('click', login)
document.getElementById('qr-button').addEventListener('click', chargeQR)
document.getElementById('verify-2fa-button').addEventListener('click', valid2FAConnection2FA)