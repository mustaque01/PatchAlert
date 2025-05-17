document.getElementById('emailForm').addEventListener('submit', function(e) {
  e.preventDefault();

  const recipient = document.getElementById('recipient').value;
  const frequency = document.getElementById('frequency').value;
  const severity = document.getElementById('severity').value;

  // Mock saving or sending to backend
  console.log("Email settings saved:", { recipient, frequency, severity });

  document.getElementById('statusMsg').textContent = 'Settings saved successfully!';
});
