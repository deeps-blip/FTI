# Use node for Vite
FROM node:20-slim

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source
COPY . .

# Expose Vite's port
EXPOSE 3000

# Start Vite in dev mode
CMD ["npm", "run", "dev"]
