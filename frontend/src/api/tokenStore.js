// Small in-memory token holder so non-React code (api/client.js) can read it.
let token = null
export const useAuthToken = {
  get: () => token,
  set: (t) => { token = t },
}
