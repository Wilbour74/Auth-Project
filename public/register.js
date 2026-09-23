document.getElementById('register-form').onsubmit = async e => {
  e.preventDefault()
  const username = document.getElementById('username').value.trim()
  const password = document.getElementById('password').value

  const response = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })


  if(response.ok){
    window.location.href = "/auth/login"
  }
}
