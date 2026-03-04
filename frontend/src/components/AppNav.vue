<template>
  <nav>
    <router-link to="/">Device Flow</router-link>
    <router-link to="/devices">📱 Mes appareils</router-link>
  </nav>
</template>

<style scoped>
nav {
  margin-bottom: 16px;
  font-size: 14px;
  display: flex;
  gap: 16px;
}

nav a {
  color: #1a73e8;
  text-decoration: none;
}

nav a:hover,
nav a.router-link-active {
  text-decoration: underline;
}
</style>
