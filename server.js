// Localize este trecho no seu server.js (em torno da linha 1000)
// Substitua o manipulador 'zip-directory' existente pelo código abaixo:

socket.on('zip-directory', (data) => {
  const { path } = data;
  
  if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
    socket.emit('sftp-error', 'No active SFTP connection');
    return;
  }
  
  const sftp = sshConnections[sessionId].sftp;
  
  // Notificar o cliente que estamos iniciando o processo de zip
  socket.emit('zip-started', { 
    path,
    message: 'Creating zip file...'
  });
  
  // Criar um arquivo zip no servidor
  const fs = require('fs');
  const archiver = require('archiver');
  const os = require('os');
  const tempPath = os.tmpdir();
  
  // Obter o nome do diretório para o caminho temporário
  const dirName = path.split('/').pop();
  
  // Caminho para o arquivo zip de saída
  const zipPath = `${path}.zip`;
  
  // Função para criar um arquivo zip de um diretório via SFTP
  const createZip = async () => {
    try {
      // Usar comando shell para criar o zip no servidor remoto
      const conn = sshConnections[sessionId].conn;
      
      conn.exec(`cd "${path.replace(/"/g, '\\"')}/.." && zip -r "${dirName}.zip" "${dirName}"`, (err, stream) => {
        if (err) {
          console.error('Zip creation error:', err);
          socket.emit('sftp-error', 'Failed to create zip: ' + err.message);
          return;
        }
        
        let errorOutput = '';
        
        stream.on('data', (data) => {
          // Output da operação zip (ignorado)
        });
        
        stream.stderr.on('data', (data) => {
          errorOutput += data.toString();
        });
        
        stream.on('close', (code) => {
          if (code !== 0) {
            console.error('Zip command failed with code', code, errorOutput);
            socket.emit('sftp-error', 'Failed to create zip: ' + errorOutput);
          } else {
            console.log('Zip created successfully');
            socket.emit('zip-complete', { path: zipPath });
          }
        });
      });
    } catch (error) {
      console.error('Zip process error:', error);
      socket.emit('sftp-error', 'Failed to create zip: ' + error.message);
    }
  };
  
  // Iniciar o processo de criação do zip
  createZip();
});
