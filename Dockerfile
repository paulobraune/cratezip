FROM node:18-alpine

# Instalar dependências do sistema, incluindo zip
RUN apk add --no-cache zip

# Create app directory
WORKDIR /app

# Copy package.json first
COPY package.json ./

# Install dependencies
RUN npm install

# Copy app source code (after installing dependencies)
COPY . .

# Expose the port the app runs on
EXPOSE 5005

# Command to run the application
CMD ["node", "server.js"]
