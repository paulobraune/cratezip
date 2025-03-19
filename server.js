const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const { Client } = require('ssh2');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');
const archiver = require('archiver');

// Create Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Configure Express
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'node_modules/monaco-editor/min')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set proper content type and encoding for all responses
app.use((req, res, next) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  next();
});

// Configure session
app.use(session({
  secret: 'ssh-client-secret',
  resave: false,
  saveUninitialized: true
}));

// Store active SSH connections
const sshConnections = {};

// Hardcoded admin credentials
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin123';

// Create a directory for saved connections if it doesn't exist
const savedConnectionsDir = path.join(__dirname, 'data');
const savedConnectionsFile = path.join(savedConnectionsDir, 'saved_connections.json');
const apiKeysFile = path.join(savedConnectionsDir, 'api_keys.json');
const chatHistoryFile = path.join(savedConnectionsDir, 'chat_history.json');

if (!fs.existsSync(savedConnectionsDir)) {
  fs.mkdirSync(savedConnectionsDir);
}

if (!fs.existsSync(savedConnectionsFile)) {
  fs.writeFileSync(savedConnectionsFile, JSON.stringify([], null, 2));
}

if (!fs.existsSync(apiKeysFile)) {
  fs.writeFileSync(apiKeysFile, JSON.stringify([], null, 2));
}

if (!fs.existsSync(chatHistoryFile)) {
  fs.writeFileSync(chatHistoryFile, JSON.stringify([], null, 2));
}

// Function to get saved connections
function getSavedConnections() {
  try {
    const data = fs.readFileSync(savedConnectionsFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading saved connections:', error);
    return [];
  }
}

// Function to get API keys
function getApiKeys() {
  try {
    const data = fs.readFileSync(apiKeysFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading API keys:', error);
    return [];
  }
}

// Function to get chat history
function getChatHistory() {
  try {
    const data = fs.readFileSync(chatHistoryFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading chat history:', error);
    return [];
  }
}

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.isAuthenticated) {
    return next();
  }
  res.redirect('/login');
};

// Routes
app.get('/login', (req, res) => {
  res.render('app_login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Check against hardcoded credentials
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.isAuthenticated = true;
    return res.redirect('/');
  }
  
  res.render('app_login', { error: 'Invalid username or password' });
});

app.get('/logout', (req, res) => {
  req.session.isAuthenticated = false;
  req.session.sshConfig = null;
  
  const sessionId = req.session.id;
  if (sshConnections[sessionId]) {
    sshConnections[sessionId].end();
    delete sshConnections[sessionId];
  }
  
  req.session.destroy();
  res.redirect('/login');
});

// Secured routes
app.get('/', isAuthenticated, (req, res) => {
  const savedConnections = getSavedConnections();
  res.render('login', { error: null, savedConnections });
});

// Get saved connections
app.get('/api/connections', isAuthenticated, (req, res) => {
  const savedConnections = getSavedConnections();
  res.json(savedConnections);
});

// Save a new connection
app.post('/api/connections', isAuthenticated, (req, res) => {
  const { name, host, port, username, password, initialPath, mode } = req.body;
  
  if (!name || !host || !username) {
    return res.status(400).json({ error: 'Name, host and username are required' });
  }
  
  try {
    const savedConnections = getSavedConnections();
    
    // Check if connection with this name already exists
    const existingIndex = savedConnections.findIndex(conn => conn.name === name);
    
    const connectionData = {
      name,
      host,
      port: port || '22',
      username,
      password, // Note: storing passwords in plain text is not secure for production
      initialPath: initialPath || '/home',
      mode: mode || 'terminal',
      createdAt: new Date().toISOString()
    };
    
    if (existingIndex !== -1) {
      // Update existing connection
      savedConnections[existingIndex] = connectionData;
    } else {
      // Add new connection
      savedConnections.push(connectionData);
    }
    
    fs.writeFileSync(savedConnectionsFile, JSON.stringify(savedConnections, null, 2));
    
    res.json({ success: true, connection: connectionData });
  } catch (error) {
    console.error('Error saving connection:', error);
    res.status(500).json({ error: 'Failed to save connection' });
  }
});

// Delete a saved connection
app.delete('/api/connections/:name', isAuthenticated, (req, res) => {
  const { name } = req.params;
  
  try {
    let savedConnections = getSavedConnections();
    savedConnections = savedConnections.filter(conn => conn.name !== name);
    
    fs.writeFileSync(savedConnectionsFile, JSON.stringify(savedConnections, null, 2));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting connection:', error);
    res.status(500).json({ error: 'Failed to delete connection' });
  }
});

// API Keys endpoints
app.get('/api/apikeys', isAuthenticated, (req, res) => {
  const apiKeys = getApiKeys();
  res.json(apiKeys);
});

app.post('/api/apikeys', isAuthenticated, (req, res) => {
  const { provider, apiKey } = req.body;
  
  if (!provider || !apiKey) {
    return res.status(400).json({ error: 'Provider and API key are required' });
  }
  
  try {
    let apiKeys = getApiKeys();
    
    // Check if API key for this provider already exists
    const existingIndex = apiKeys.findIndex(key => key.provider === provider);
    
    const apiKeyData = {
      provider,
      apiKey,
      updatedAt: new Date().toISOString()
    };
    
    if (existingIndex !== -1) {
      // Update existing API key
      apiKeys[existingIndex] = apiKeyData;
    } else {
      // Add new API key
      apiKeys.push(apiKeyData);
    }
    
    fs.writeFileSync(apiKeysFile, JSON.stringify(apiKeys, null, 2));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving API key:', error);
    res.status(500).json({ error: 'Failed to save API key' });
  }
});

app.delete('/api/apikeys/:provider', isAuthenticated, (req, res) => {
  const { provider } = req.params;
  
  try {
    let apiKeys = getApiKeys();
    apiKeys = apiKeys.filter(key => key.provider !== provider);
    
    fs.writeFileSync(apiKeysFile, JSON.stringify(apiKeys, null, 2));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({ error: 'Failed to delete API key' });
  }
});

app.post('/api/apikeys/test', isAuthenticated, async (req, res) => {
  const { provider, apiKey } = req.body;
  
  if (!provider || !apiKey) {
    return res.status(400).json({ error: 'Provider and API key are required' });
  }
  
  try {
    let testResult = { success: false, error: 'Unsupported provider' };
    
    // Test API key based on provider
    switch (provider) {
      case 'openai':
        testResult = await testOpenAIKey(apiKey);
        break;
      case 'deepseek':
        testResult = await testDeepseekKey(apiKey);
        break;
      case 'anthropic':
        testResult = await testAnthropicKey(apiKey);
        break;
      default:
        testResult = { success: false, error: 'Unsupported provider' };
    }
    
    res.json(testResult);
  } catch (error) {
    console.error('Error testing API key:', error);
    res.status(500).json({ success: false, error: 'Failed to test API key' });
  }
});

// Test functions for API keys
async function testOpenAIKey(apiKey) {
  try {
    const response = await fetch('https://api.openai.com/v1/models', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });
    
    const data = await response.json();
    
    if (response.ok) {
      return { 
        success: true, 
        message: `Connection successful. Available models: ${data.data.length}` 
      };
    } else {
      return { 
        success: false, 
        error: data.error?.message || 'Invalid API key or API error' 
      };
    }
  } catch (error) {
    console.error('OpenAI API test error:', error);
    return { success: false, error: 'Network error or invalid API key' };
  }
}

async function testDeepseekKey(apiKey) {
  try {
    // Simplified test for DeepSeek - in a real application, you'd use their actual API endpoint
    const response = await fetch('https://api.deepseek.com/v1/models', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Check if status is 401 (unauthorized) - means API key is invalid
    if (response.status === 401) {
      return { success: false, error: 'Invalid API key' };
    }
    
    // For demo purposes, we'll consider any non-401 response as "potentially valid"
    // In a real application, you'd properly validate against DeepSeek's API
    return { 
      success: true, 
      message: 'Connection potentially valid (simulated test)' 
    };
  } catch (error) {
    // If there's a network error or CORS issue, we'll assume the key might be valid
    // but there's an issue with our test method
    console.error('DeepSeek API test error:', error);
    return { 
      success: true, 
      message: 'API key format valid, but full verification not available in demo mode' 
    };
  }
}

async function testAnthropicKey(apiKey) {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'anthropic-version': '2023-06-01',
        'x-api-key': apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-instant-1.2',
        max_tokens: 10,
        messages: [
          {
            role: 'user',
            content: 'Hello, this is an API test.'
          }
        ]
      })
    });
    
    const data = await response.json();
    
    // Check if response indicates invalid key
    if (response.status === 401 || response.status === 403) {
      return { 
        success: false, 
        error: data.error?.message || 'Invalid API key' 
      };
    }
    
    return { 
      success: true, 
      message: 'API key valid' 
    };
  } catch (error) {
    console.error('Anthropic API test error:', error);
    // For demo purposes, if there's a network error, we'll assume the key format is valid
    return { 
      success: true, 
      message: 'API key format valid, but full verification not available in demo mode' 
    };
  }
}

// Chat history endpoints
app.get('/api/chat/:projectId', isAuthenticated, (req, res) => {
  const { projectId } = req.params;
  const chatHistory = getChatHistory();
  
  // Find chat history for this project
  const projectHistory = chatHistory.find(chat => chat.project_id === projectId);
  
  if (projectHistory) {
    res.json(projectHistory);
  } else {
    res.json({ 
      project_id: projectId,
      timestamp: new Date().toISOString(),
      messages: [],
      file_context: [] 
    });
  }
});

app.post('/api/chat/:projectId', isAuthenticated, (req, res) => {
  const { projectId } = req.params;
  const { messages, file_context } = req.body;
  
  if (!projectId) {
    return res.status(400).json({ error: 'Project ID is required' });
  }
  
  try {
    let chatHistory = getChatHistory();
    
    // Check if chat history for this project already exists
    const existingIndex = chatHistory.findIndex(chat => chat.project_id === projectId);
    
    const chatData = {
      project_id: projectId,
      timestamp: new Date().toISOString(),
      messages: messages || [],
      file_context: file_context || []
    };
    
    if (existingIndex !== -1) {
      // Update existing chat history
      chatHistory[existingIndex] = chatData;
    } else {
      // Add new chat history
      chatHistory.push(chatData);
    }
    
    fs.writeFileSync(chatHistoryFile, JSON.stringify(chatHistory, null, 2));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving chat history:', error);
    res.status(500).json({ error: 'Failed to save chat history' });
  }
});

app.delete('/api/chat/:projectId', isAuthenticated, (req, res) => {
  const { projectId } = req.params;
  
  try {
    let chatHistory = getChatHistory();
    chatHistory = chatHistory.filter(chat => chat.project_id !== projectId);
    
    fs.writeFileSync(chatHistoryFile, JSON.stringify(chatHistory, null, 2));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting chat history:', error);
    res.status(500).json({ error: 'Failed to delete chat history' });
  }
});

app.post('/connect', isAuthenticated, (req, res) => {
  const { host, port, username, password, mode, initialPathOption, initialPath } = req.body;
  
  if (!host || !username) {
    return res.render('login', { error: 'Host and username are required', savedConnections: getSavedConnections() });
  }
  
  // Determine initial directory path
  let directoryPath = '/home';
  
  if (initialPathOption === 'custom' && initialPath && initialPath.trim()) {
    directoryPath = initialPath.trim();
  }

  // Store connection info in session
  req.session.sshConfig = {
    host,
    port: port || 22,
    username,
    password,
    mode: mode || 'terminal',
    initialPath: directoryPath
  };

  // Redirect based on selected mode
  if (mode === 'filemanager') {
    res.redirect('/file_manager');
  } else if (mode === 'chat') {
    res.redirect('/chat');
  } else {
    res.redirect('/terminal');
  }
});

app.get('/terminal', isAuthenticated, (req, res) => {
  if (!req.session.sshConfig) {
    return res.redirect('/');
  }
  
  // If switching from another mode, update the mode
  if (req.query.switchMode) {
    req.session.sshConfig.mode = 'terminal';
  }
  
  res.render('terminal', { 
    host: req.session.sshConfig.host,
    port: req.session.sshConfig.port,
    username: req.session.sshConfig.username,
    password: req.session.sshConfig.password,
    initialPath: req.session.sshConfig.initialPath
  });
});

app.get('/file_manager', isAuthenticated, (req, res) => {
  if (!req.session.sshConfig) {
    return res.redirect('/');
  }
  
  // If switching from another mode, update the mode
  if (req.query.switchMode) {
    req.session.sshConfig.mode = 'filemanager';
  }
  
  res.render('file_manager', { 
    host: req.session.sshConfig.host,
    port: req.session.sshConfig.port,
    username: req.session.sshConfig.username,
    password: req.session.sshConfig.password,
    initialPath: req.session.sshConfig.initialPath
  });
});

app.get('/chat', isAuthenticated, (req, res) => {
  if (!req.session.sshConfig) {
    return res.redirect('/');
  }
  
  // If switching from another mode, update the mode
  if (req.query.switchMode) {
    req.session.sshConfig.mode = 'chat';
  }
  
  res.render('chat', { 
    host: req.session.sshConfig.host,
    port: req.session.sshConfig.port,
    username: req.session.sshConfig.username,
    password: req.session.sshConfig.password,
    initialPath: req.session.sshConfig.initialPath
  });
});

app.get('/disconnect', isAuthenticated, (req, res) => {
  const sessionId = req.session.id;
  
  if (sshConnections[sessionId]) {
    sshConnections[sessionId].end();
    delete sshConnections[sessionId];
  }
  
  req.session.sshConfig = null;
  res.redirect('/');
});

// File download endpoint
app.get('/file/download', isAuthenticated, (req, res) => {
  const { path, sessionId } = req.query;
  
  if (!path || !sessionId) {
    return res.status(400).send('Missing path or session ID');
  }
  
  const sshConn = sshConnections[sessionId];
  if (!sshConn || !sshConn.sftp) {
    return res.status(404).send('No active SFTP connection');
  }
  
  // Extract filename from path
  const filename = path.split('/').pop();
  
  // Set headers for file download
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  
  // Stream the file to the response
  sshConn.sftp.createReadStream(path).pipe(res);
});

// New endpoint for zip directory download - FIXED VERSION
app.post('/file/zip-download', isAuthenticated, (req, res) => {
  const { path, sessionId } = req.body;
  
  if (!path || !sessionId) {
    return res.status(400).json({ error: 'Missing path or session ID' });
  }
  
  const sshConn = sshConnections[sessionId];
  if (!sshConn || !sshConn.sftp) {
    return res.status(404).json({ error: 'No active SFTP connection' });
  }
  
  // Create a unique ID for this zip operation
  const zipId = Date.now().toString();
  
  // Get directory name for the zip file
  const dirName = path.split('/').pop() || 'folder';
  const zipFileName = `${dirName}-${zipId}.zip`;
  
  // Create a write stream for the response
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${zipFileName}"`);
  
  // Create a new zip archive
  const archive = archiver('zip', {
    zlib: { level: 9 } // Sets the compression level
  });
  
  // Pipe the archive to the response
  archive.pipe(res);
  
  // Handle archive errors
  archive.on('error', (err) => {
    console.error('Archive error:', err);
    res.status(500).end();
  });
  
  // Function to recursively add files to the archive
  const addDirectoryToArchive = (directoryPath, relativePath = '') => {
    return new Promise((resolve, reject) => {
      sshConn.sftp.readdir(directoryPath, async (err, list) => {
        if (err) {
          console.error('Error reading directory:', err);
          return reject(err);
        }
        
        try {
          // Process all files in the directory
          for (const item of list) {
            const fullPath = directoryPath + '/' + item.filename;
            const archivePath = relativePath ? relativePath + '/' + item.filename : item.filename;
            
            if (item.attrs.isDirectory()) {
              // Recursively add subdirectories
              await addDirectoryToArchive(fullPath, archivePath);
            } else {
              try {
                // Add file to the archive
                const fileStream = sshConn.sftp.createReadStream(fullPath);
                archive.append(fileStream, { name: archivePath });
                
                // Handle potential errors on the file stream
                fileStream.on('error', (err) => {
                  console.error(`Error reading file ${fullPath}:`, err);
                  // Continue with other files instead of failing the whole process
                });
              } catch (fileErr) {
                console.error(`Error adding file ${fullPath} to archive:`, fileErr);
                // Continue with other files
              }
            }
          }
          
          resolve();
        } catch (error) {
          console.error('Error processing directory contents:', error);
          reject(error);
        }
      });
    });
  };
  
  // Start the zip process
  addDirectoryToArchive(path, '')
    .then(() => {
      // Finalize the archive and send the response
      archive.finalize();
    })
    .catch((error) => {
      console.error('Zip process error:', error);
      // Don't end the response here, as we've already started streaming
      // Instead, finalize the archive with whatever files we managed to process
      archive.finalize();
    });
});

// File content endpoint - For monaco editor
app.get('/file/content', isAuthenticated, (req, res) => {
  const { path, sessionId } = req.query;
  
  if (!path || !sessionId) {
    return res.status(400).json({ error: 'Missing path or session ID' });
  }
  
  const sshConn = sshConnections[sessionId];
  if (!sshConn || !sshConn.sftp) {
    return res.status(404).json({ error: 'No active SFTP connection' });
  }
  
  // Stream the file content
  let fileContent = '';
  const readStream = sshConn.sftp.createReadStream(path);
  
  readStream.on('data', (data) => {
    fileContent += data.toString('utf8');
  });
  
  readStream.on('end', () => {
    res.json({ content: fileContent });
  });
  
  readStream.on('error', (err) => {
    res.status(500).json({ error: 'Failed to read file: ' + err.message });
  });
});

// Save file content endpoint
app.post('/file/save', isAuthenticated, (req, res) => {
  const { path, content, sessionId } = req.body;
  
  if (!path || content === undefined || !sessionId) {
    return res.status(400).json({ error: 'Missing path, content, or session ID' });
  }
  
  const sshConn = sshConnections[sessionId];
  if (!sshConn || !sshConn.sftp) {
    return res.status(404).json({ error: 'No active SFTP connection' });
  }
  
  // Create write stream
  const writeStream = sshConn.sftp.createWriteStream(path);
  
  writeStream.on('error', (err) => {
    res.status(500).json({ error: 'Failed to save file: ' + err.message });
  });
  
  writeStream.on('close', () => {
    res.json({ success: true });
  });
  
  // Write content to file
  writeStream.end(content);
});

// Socket.IO connection for terminal
io.on('connection', (socket) => {
  const sessionId = socket.handshake.query.sessionId;
  
  // Handle SSH terminal connections
  socket.on('connect-ssh', (data) => {
    // Create a new SSH client
    const conn = new Client();
    
    conn.on('ready', () => {
      socket.emit('message', 'SSH connection established successfully!\n');
      
      // Start shell session
      conn.shell((err, stream) => {
        if (err) {
          socket.emit('error', 'Shell error: ' + err.message);
          conn.end();
          return;
        }
        
        // Store the stream for this connection
        sshConnections[sessionId] = { conn, stream };
        
        // For collecting complete chunks before processing
        let dataBuffer = '';
        
        // Handle data from server
        stream.on('data', (data) => {
          // Combine data into buffer to ensure complete UTF-8 characters
          dataBuffer += data.toString('utf8');
          
          // Process all complete ANSI sequences and characters in buffer
          socket.emit('response', dataBuffer);
          
          // Clear the buffer after processing
          dataBuffer = '';
        });
        
        stream.on('close', () => {
          socket.emit('message', 'SSH connection closed by server');
          if (sshConnections[sessionId]) {
            conn.end();
            delete sshConnections[sessionId];
          }
        });
        
        stream.stderr.on('data', (data) => {
          socket.emit('error', data.toString('utf8'));
        });
        
        // Change to initial directory if provided
        if (data.initialPath && data.initialPath !== '/home') {
          stream.write(`cd ${data.initialPath}\n`);
        }
      });
    });
    
    conn.on('error', (err) => {
      socket.emit('error', 'Connection error: ' + err.message);
    });
    
    conn.on('close', () => {
      socket.emit('message', 'Connection closed');
      if (sshConnections[sessionId]) {
        delete sshConnections[sessionId];
      }
    });
    
    // Connect using session data
    conn.connect(data.sshConfig);
  });
  
  // Handle terminal commands
  socket.on('command', (data) => {
    const { command } = data;
    
    if (sshConnections[sessionId] && sshConnections[sessionId].stream) {
      sshConnections[sessionId].stream.write(command + '\n');
    } else {
      socket.emit('error', 'No active SSH connection');
    }
  });
  
  // Handle SFTP connections for file manager
  socket.on('connect-sftp', (data) => {
    // Create a new SSH client
    const conn = new Client();
    
    conn.on('ready', () => {
      // Create SFTP session
      conn.sftp((err, sftp) => {
        if (err) {
          socket.emit('sftp-error', 'SFTP error: ' + err.message);
          conn.end();
          return;
        }
        
        // Store the SFTP connection
        sshConnections[sessionId] = { conn, sftp };
        
        socket.emit('sftp-connected', { initialPath: data.initialPath });
      });
    });
    
    conn.on('error', (err) => {
      socket.emit('sftp-error', 'Connection error: ' + err.message);
    });
    
    conn.on('close', () => {
      if (sshConnections[sessionId]) {
        delete sshConnections[sessionId];
      }
    });
    
    // Connect using session data
    conn.connect(data.sshConfig);
  });
  
  // Handle SFTP operations
  socket.on('list-directory', (data) => {
    const { path } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    
    sftp.readdir(path, (err, list) => {
      if (err) {
        socket.emit('sftp-error', 'Failed to read directory: ' + err.message);
        return;
      }
      
      // Process file list
      const files = list.map(item => {
        return {
          name: item.filename,
          size: item.attrs.size,
          isDirectory: item.attrs.isDirectory(),
          modifyTime: new Date(item.attrs.mtime * 1000),
          permissions: item.attrs.mode,
          owner: item.attrs.uid
        };
      });
      
      socket.emit('directory-list', { path, files });
    });
  });
  
  // Handle directory zipping - FIXED VERSION
  socket.on('zip-directory', (data) => {
    const { path } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    // Only notify the client that we're starting the zip process
    // The actual download will happen via a separate HTTP request
    socket.emit('zip-started', { 
      path,
      message: 'Preparing zip file. Download will start automatically when ready.'
    });
    
    // No operations related to file renaming or deletion should be here
    // The client will initiate the actual download separately
  });
  
  // Handle file uploads
  socket.on('upload-file', (data) => {
    const { path, data: fileData } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    
    // Create write stream
    const writeStream = sftp.createWriteStream(path);
    
    writeStream.on('error', (err) => {
      socket.emit('sftp-error', 'Upload failed: ' + err.message);
    });
    
    writeStream.on('close', () => {
      socket.emit('upload-complete');
    });
    
    // Convert ArrayBuffer to Buffer and write
    const buffer = Buffer.from(fileData);
    writeStream.end(buffer);
  });
  
  // Handle file/directory deletion
  socket.on('delete-file', (data) => {
    const { path, isDirectory } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    
    if (isDirectory) {
      // For directories, we need to ensure they're empty first
      // This is a simplified version - in production you'd want recursive deletion
      sftp.rmdir(path, (err) => {
        if (err) {
          socket.emit('sftp-error', 'Failed to delete directory: ' + err.message);
          return;
        }
        socket.emit('delete-complete');
      });
    } else {
      sftp.unlink(path, (err) => {
        if (err) {
          socket.emit('sftp-error', 'Failed to delete file: ' + err.message);
          return;
        }
        socket.emit('delete-complete');
      });
    }
  });
  
  // Handle file/directory rename
  socket.on('rename-file', (data) => {
    const { oldPath, newPath } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    
    sftp.rename(oldPath, newPath, (err) => {
      if (err) {
        socket.emit('sftp-error', 'Failed to rename: ' + err.message);
        return;
      }
      socket.emit('rename-complete');
    });
  });
  
  // Handle folder creation
  socket.on('create-folder', (data) => {
    const { path } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    
    sftp.mkdir(path, (err) => {
      if (err) {
        socket.emit('sftp-error', 'Failed to create folder: ' + err.message);
        return;
      }
      socket.emit('folder-created');
    });
  });
  
  // Handle file content reading for editing
  socket.on('read-file', (data) => {
    const { path } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    let content = '';
    
    const readStream = sftp.createReadStream(path);
    
    readStream.on('data', (chunk) => {
      content += chunk.toString('utf8');
    });
    
    readStream.on('end', () => {
      socket.emit('file-content', { path, content });
    });
    
    readStream.on('error', (err) => {
      socket.emit('sftp-error', 'Failed to read file: ' + err.message);
    });
  });
  
  // Handle file saving after editing
  socket.on('save-file', (data) => {
    const { path, content } = data;
    
    if (!sshConnections[sessionId] || !sshConnections[sessionId].sftp) {
      socket.emit('sftp-error', 'No active SFTP connection');
      return;
    }
    
    const sftp = sshConnections[sessionId].sftp;
    
    const writeStream = sftp.createWriteStream(path);
    
    writeStream.on('error', (err) => {
      socket.emit('sftp-error', 'Failed to save file: ' + err.message);
    });
    
    writeStream.on('close', () => {
      socket.emit('file-saved', { path });
    });
    
    writeStream.end(content);
  });
  
  // Handle chat history saving
  socket.on('save-chat-history', (history) => {
    try {
      let chatHistory = getChatHistory();
      
      // Check if chat history for this project already exists
      const existingIndex = chatHistory.findIndex(chat => chat.project_id === history.project_id);
      
      if (existingIndex !== -1) {
        // Update existing chat history
        chatHistory[existingIndex] = history;
      } else {
        // Add new chat history
        chatHistory.push(history);
      }
      
      fs.writeFileSync(chatHistoryFile, JSON.stringify(chatHistory, null, 2));
      
      socket.emit('chat-history-saved', { success: true });
    } catch (error) {
      console.error('Error saving chat history:', error);
      socket.emit('chat-history-saved', { success: false, error: 'Failed to save chat history' });
    }
  });
  
  // Cleanup connections on disconnect
  socket.on('disconnect', () => {
    if (sshConnections[sessionId]) {
      sshConnections[sessionId].conn.end();
      delete sshConnections[sessionId];
    }
  });
});

// Create views directory if it doesn't exist
if (!fs.existsSync('./views')) {
  fs.mkdirSync('./views');
}

// Create public directory if it doesn't exist
if (!fs.existsSync('./public')) {
  fs.mkdirSync('./public');
}

// Create subdirectories in public
if (!fs.existsSync('./public/css')) {
  fs.mkdirSync('./public/css');
}

if (!fs.existsSync('./public/images')) {
  fs.mkdirSync('./public/images');
}

// Start server
const PORT = process.env.PORT || 5003;
server.listen(PORT, () => {
  console.log(`SSH Client server running on http://localhost:${PORT}`);
  console.log(`Use the following credentials to login:`);
  console.log(`Username: ${ADMIN_USERNAME}`);
  console.log(`Password: ${ADMIN_PASSWORD}`);
});