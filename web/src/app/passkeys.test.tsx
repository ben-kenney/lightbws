import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { Providers } from "./Providers"
import type { Session, TwoFactorStatus } from "./types"

const mocks = vi.hoisted(() => ({
  authConfig: vi.fn(),
  login: vi.fn(),
  loginSecondFactor: vi.fn(),
  logout: vi.fn(),
  overview: vi.fn(),
  session: vi.fn(),
  twoFactorStatus: vi.fn(),
  passkeys: vi.fn(),
  passkeyRegisterOptions: vi.fn(),
  passkeyRegisterVerify: vi.fn(),
  renamePasskey: vi.fn(),
  removePasskey: vi.fn(),
  passkeyChallengeOptions: vi.fn(),
  passkeyChallengeVerify: vi.fn(),
  passkeySignInOptions: vi.fn(),
  passkeySignInVerify: vi.fn(),
}))
const browser = vi.hoisted(() => ({
  supported: true,
  createPasskey: vi.fn(),
  getPasskey: vi.fn(),
}))

vi.mock("./api", () => {
  class ApiError extends Error {
    constructor(public status: number, public code: string) {
      super(code)
    }
  }
  return { ApiError, api: mocks }
})
vi.mock("./webauthn", () => ({
  passkeysSupported: () => browser.supported,
  passkeyCancelled: (error: unknown) => error instanceof DOMException && error.name === "NotAllowedError",
  createPasskey: browser.createPasskey,
  getPasskey: browser.getPasskey,
}))

import { ApiError } from "./api"
import { App } from "./App"

const session: Session = {
  csrfToken: "csrf",
  user: { id: "user-1", username: "admin", displayName: "Administrator", role: "admin", disabled: false, createdAt: 1, updatedAt: 1, lastLoginAt: 1 },
}
const status: TwoFactorStatus = { enabled: true, totpEnabled: false, passkeyCount: 1, recoveryCodesRemaining: 10, required: false }
const options = { publicKey: { challenge: "Y2hhbGxlbmdl" } }
const assertion = { id: "credential" }
const passkey = { id: "passkey-1", name: "Laptop", createdAt: 1_700_000_000, lastUsedAt: null, synced: true }

function renderApp() {
  render(<Providers><App /></Providers>)
}

describe("passkeys", () => {
  afterEach(cleanup)

  beforeEach(() => {
    vi.resetAllMocks()
    browser.supported = true
    const stored = new Map<string, string>()
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      value: {
        clear: () => stored.clear(),
        getItem: (key: string) => stored.get(key) ?? null,
        removeItem: (key: string) => stored.delete(key),
        setItem: (key: string, value: string) => stored.set(key, value),
      },
    })
    localStorage.setItem("lightbws-locale", "en")
    localStorage.setItem("lightbws-onboarding-v1", "done")
    history.replaceState(null, "", "/")
    mocks.overview.mockResolvedValue({ projects: 0, secrets: 0, trash: 0 })
    mocks.authConfig.mockResolvedValue({ initialized: true, localEnabled: true, passkeysEnabled: true })
    mocks.passkeys.mockResolvedValue([])
  })

  it("signs in with a passkey alone, and stays quiet when the prompt is dismissed", async () => {
    mocks.session.mockRejectedValue(new Error("signed out"))
    mocks.passkeySignInOptions.mockResolvedValue(options)
    browser.getPasskey.mockRejectedValueOnce(new DOMException("dismissed", "NotAllowedError")).mockResolvedValue(assertion)
    mocks.passkeySignInVerify.mockRejectedValueOnce(new ApiError(401, "UNAUTHORIZED")).mockResolvedValue(session)
    renderApp()

    const button = await screen.findByRole("button", { name: "Sign in with a passkey" })
    await userEvent.click(button)
    await waitFor(() => expect(browser.getPasskey).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    expect(mocks.passkeySignInVerify).not.toHaveBeenCalled()

    await userEvent.click(button)
    expect(await screen.findByText("That passkey could not be verified.")).toBeInTheDocument()

    await userEvent.click(button)
    await waitFor(() => expect(location.pathname).toBe("/"))
    expect(browser.getPasskey).toHaveBeenLastCalledWith(options)
    expect(mocks.passkeySignInVerify).toHaveBeenLastCalledWith(assertion)
  })

  it("shows no passkey sign-in when the server or the browser cannot do passkeys", async () => {
    mocks.session.mockRejectedValue(new Error("signed out"))
    mocks.authConfig.mockResolvedValue({ initialized: true, localEnabled: true, passkeysEnabled: false })
    renderApp()
    await screen.findByRole("button", { name: "Sign in" })
    await waitFor(() => expect(mocks.authConfig).toHaveBeenCalled())
    expect(screen.queryByRole("button", { name: "Sign in with a passkey" })).not.toBeInTheDocument()
    cleanup()

    browser.supported = false
    mocks.authConfig.mockClear()
    renderApp()
    await screen.findByRole("button", { name: "Sign in" })
    expect(mocks.authConfig).not.toHaveBeenCalled()
    expect(screen.queryByRole("button", { name: "Sign in with a passkey" })).not.toBeInTheDocument()
  })

  it("offers the passkey as the step after the password, next to a recovery code", async () => {
    mocks.session.mockRejectedValue(new Error("signed out"))
    mocks.login.mockResolvedValue({ twoFactorRequired: true, challenge: "challenge-token", methods: ["passkey"] })
    mocks.passkeyChallengeOptions.mockResolvedValue(options)
    browser.getPasskey.mockResolvedValue(assertion)
    mocks.passkeyChallengeVerify.mockResolvedValue(session)
    renderApp()

    await screen.findByRole("button", { name: "Sign in with a passkey" })
    await userEvent.type(screen.getByLabelText(/^Username/), "admin")
    await userEvent.type(screen.getByLabelText(/^Password/), "password")
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }))

    const use = await screen.findByRole("button", { name: "Use your passkey" })
    expect(screen.getByRole("button", { name: "Use a recovery code instead" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Use an authenticator code instead" })).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/^Authenticator code/)).not.toBeInTheDocument()
    await userEvent.click(use)
    await waitFor(() => expect(location.pathname).toBe("/"))
    expect(mocks.passkeyChallengeOptions).toHaveBeenCalledWith("challenge-token")
    expect(mocks.passkeyChallengeVerify).toHaveBeenCalledWith(assertion)
  })

  it("adds, renames and removes passkeys in Settings", async () => {
    history.replaceState(null, "", "/#settings")
    mocks.session.mockResolvedValue(session)
    mocks.twoFactorStatus.mockResolvedValueOnce({ ...status, enabled: false, passkeyCount: 0, recoveryCodesRemaining: 0 }).mockResolvedValue(status)
    mocks.passkeys.mockResolvedValueOnce([]).mockResolvedValue([passkey])
    mocks.passkeyRegisterOptions.mockResolvedValue(options)
    browser.createPasskey.mockResolvedValue({ id: "credential" })
    mocks.passkeyRegisterVerify.mockResolvedValue({ passkey, recoveryCodes: ["aaaa-bbbb-cccc"] })
    mocks.renamePasskey.mockResolvedValue({ ...passkey, name: "Work laptop" })
    mocks.removePasskey.mockResolvedValue(undefined)
    renderApp()

    await userEvent.click(await screen.findByRole("button", { name: "Add a passkey" }))
    let dialog = await screen.findByRole("dialog")
    await userEvent.type(within(dialog).getByLabelText(/^Current password/), "password")
    await userEvent.type(within(dialog).getByLabelText(/^Passkey name/), " Laptop ")
    await userEvent.click(within(dialog).getByRole("button", { name: "Create passkey" }))
    expect(await within(dialog).findByText("aaaa-bbbb-cccc")).toBeInTheDocument()
    expect(mocks.passkeyRegisterOptions).toHaveBeenCalledWith("password")
    expect(browser.createPasskey).toHaveBeenCalledWith(options)
    expect(mocks.passkeyRegisterVerify).toHaveBeenCalledWith("Laptop", { id: "credential" })
    await userEvent.click(within(dialog).getByRole("button", { name: "I have saved these codes" }))

    expect(await screen.findByText("Laptop")).toBeInTheDocument()
    expect(screen.getByText(/^Synced/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole("button", { name: "Rename · Laptop" }))
    dialog = await screen.findByRole("dialog")
    const name = within(dialog).getByLabelText(/^Passkey name/)
    await userEvent.clear(name)
    await userEvent.type(name, "Work laptop")
    await userEvent.click(within(dialog).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(mocks.renamePasskey).toHaveBeenCalledWith("passkey-1", "Work laptop"))

    await userEvent.click(await screen.findByRole("button", { name: "Remove passkey · Laptop" }))
    dialog = await screen.findByRole("dialog")
    await userEvent.type(within(dialog).getByLabelText(/^Current password/), "password")
    await userEvent.click(within(dialog).getByRole("button", { name: "Remove passkey" }))
    await waitFor(() => expect(mocks.removePasskey).toHaveBeenCalledWith("passkey-1", "password"))
  })

  it("explains why passkeys are unavailable and keeps the only required factor", async () => {
    history.replaceState(null, "", "/#settings")
    mocks.session.mockResolvedValue(session)
    mocks.twoFactorStatus.mockResolvedValue({ ...status, required: true })
    mocks.passkeys.mockResolvedValue([passkey])
    renderApp()

    expect(await screen.findByRole("button", { name: "Remove passkey · Laptop" })).toHaveAttribute("aria-disabled", "true")
    cleanup()

    mocks.authConfig.mockResolvedValue({ initialized: true, localEnabled: true, passkeysEnabled: false })
    renderApp()
    expect(await screen.findByText(/Passkeys need HTTPS/)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Add a passkey" })).not.toBeInTheDocument()
  })
})
