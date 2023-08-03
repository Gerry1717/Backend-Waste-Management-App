# Use a base image that includes both Node.js and Python
FROM nikolaik/python-nodejs:python3.8-nodejs16

# Set the working directory inside the container
WORKDIR /app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy package.json and package-lock.json
COPY package*.json ./

# Install the application dependencies
RUN npm ci

# Copy the rest of your application code to the container (exclude node_modules)
COPY . .

# Expose the desired port
EXPOSE 8080

# Start the application
CMD ["node", "app.js"]
