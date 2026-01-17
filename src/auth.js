// Fungsi untuk memeriksa status login
async function checkAuth() {
  try {
    const response = await fetch("/api/check-auth", {
      credentials: "include",
    });
    const data = await response.json();
    return data;
  } catch (err) {
    console.error("Auth check error:", err);
    return { authenticated: false };
  }
}

// Fungsi untuk logout
async function logout() {
  try {
    const response = await fetch("/api/logout", {
      method: "POST",
      credentials: "include",
    });
    const data = await response.json();

    if (data.success) {
      window.location.href = "/login";
    }
  } catch (err) {
    console.error("Logout error:", err);
  }
}

// Fungsi untuk memproteksi halaman
async function protectPage() {
  const authStatus = await checkAuth();

  if (
    !authStatus.authenticated &&
    !window.location.pathname.includes("/login")
  ) {
    window.location.href = "/login";
    return false;
  }

  return authStatus;
}

// Fungsi untuk menambahkan header auth ke request
function withAuth(headers = {}) {
  return {
    ...headers,
    "Content-Type": "application/json",
  };
}

// Export fungsi
export { checkAuth, logout, protectPage, withAuth };
