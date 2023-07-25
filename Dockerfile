# Use a Node.js base image
FROM node:14

# Set the working directory inside the container
WORKDIR /app

# Copy the application files to the container
COPY package.json package-lock.json ./
COPY . .

# Install the application dependencies
RUN npm install

# Expose the desired port
EXPOSE 443

# Start the application
CMD ["npm", "start"]
