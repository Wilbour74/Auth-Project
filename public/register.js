document.getElementById('register-form').onsubmit = async e => {
  e.preventDefault()
  const username = document.getElementById('username').value.trim()
  const password = document.getElementById('password').value

  const response = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })

  const data = await response.json();

  const messageElement = document.getElementById('message')
  const batContainer = document.getElementById('bat-computer-container')
  if (response.ok) {
    messageElement.classList.add('success')
    messageElement.classList.remove('error')
    messageElement.innerText = data
    batContainer.style.display = 'block'
  } else {
    messageElement.classList.add('error')
    messageElement.classList.remove('success')
    messageElement.innerText = data
  }
}
