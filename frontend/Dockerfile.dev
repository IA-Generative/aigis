FROM node:20-alpine
WORKDIR /app

# Installer les dépendances séparément pour profiter du cache Docker
COPY package.json package-lock.json* ./
RUN npm i --ci

# Le code source est monté via volume — pas de COPY ici
EXPOSE 5173

CMD ["npm", "run", "dev"]
