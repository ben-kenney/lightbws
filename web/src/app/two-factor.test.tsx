import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { Providers } from "./Providers"
import type { Session, TwoFactorStatus } from "./types"

const mocks = vi.hoisted(() => ({
  login: vi.fn(),
  loginSecondFactor: vi.fn(),
  logout: vi.fn(),
  overview: vi.fn(),
  session: vi.fn(),
  twoFactorStatus: vi.fn(),
  setupTotp: vi.fn(),
  confirmTotp: vi.fn(),
  disableTotp: vi.fn(),
  changePassword: vi.fn(),
  users: vi.fn(),
  resetUserTwoFactor: vi.fn(),
}))

vi.mock("./api", () => {
  class ApiError extends Error {
    constructor(public status: number, public code: string) {
      super(code)
    }
  }
  return { ApiError, api: mocks }
})

import { ApiError } from "./api"
import { App } from "./App"

const session: Session = {
  csrfToken: "csrf",
  user: { id: "user-1", username: "admin", displayName: "Administrator", role: "admin", disabled: false, createdAt: 1, updatedAt: 1, lastLoginAt: 1 },
}
const off: TwoFactorStatus = { enabled: false, totpEnabled: false, passkeyCount: 0, recoveryCodesRemaining: 0, required: false }
const on: TwoFactorStatus = { enabled: true, totpEnabled: true, passkeyCount: 0, recoveryCodesRemaining: 10, required: false }
const challenge = { twoFactorRequired: true, challenge: "challenge-token", methods: ["totp", "recovery_code"] }

async function enterPassword() {
  await userEvent.type(await screen.findByLabelText(/^Username/), "admin")
  await userEvent.type(screen.getByLabelText(/^Password/), "password")
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }))
}

describe("two-factor authentication", () => {
  afterEach(cleanup)

  beforeEach(() => {
    vi.resetAllMocks()
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
    mocks.logout.mockResolvedValue(undefined)
  })

  it("asks for an authenticator code after the password and signs in", async () => {
    mocks.session.mockRejectedValue(new Error("signed out"))
    mocks.login.mockResolvedValue(challenge)
    mocks.loginSecondFactor.mockRejectedValueOnce(new ApiError(401, "UNAUTHORIZED")).mockResolvedValue(session)
    render(<Providers><App /></Providers>)

    await enterPassword()
    expect(await screen.findByRole("heading", { level: 1, name: "Two-step verification" })).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(/^Authenticator code/), "000000")
    await userEvent.click(screen.getByRole("button", { name: "Verify" }))
    expect(await screen.findByText("That code is not correct.")).toBeInTheDocument()
    expect(screen.getByLabelText(/^Authenticator code/)).toHaveValue("")

    await userEvent.type(screen.getByLabelText(/^Authenticator code/), " 123456 ")
    await userEvent.click(screen.getByRole("button", { name: "Verify" }))
    await waitFor(() => expect(location.pathname).toBe("/"))
    expect(mocks.loginSecondFactor).toHaveBeenLastCalledWith("challenge-token", { code: "123456" })
  })

  it("accepts a recovery code and returns to the password after five wrong attempts", async () => {
    mocks.session.mockRejectedValue(new Error("signed out"))
    mocks.login.mockResolvedValue(challenge)
    mocks.loginSecondFactor.mockRejectedValue(new ApiError(401, "UNAUTHORIZED"))
    render(<Providers><App /></Providers>)

    await enterPassword()
    await userEvent.click(await screen.findByRole("button", { name: "Use a recovery code instead" }))
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await userEvent.type(screen.getByLabelText(/^Recovery code/), "aaaa-bbbb-cccc")
      await userEvent.click(screen.getByRole("button", { name: "Verify" }))
      await waitFor(() => expect(mocks.loginSecondFactor).toHaveBeenCalledTimes(attempt + 1))
    }
    expect(mocks.loginSecondFactor).toHaveBeenLastCalledWith("challenge-token", { recoveryCode: "aaaa-bbbb-cccc" })
    expect(await screen.findByText("The sign-in attempt ended. Enter your password again.")).toBeInTheDocument()
    expect(screen.getByLabelText(/^Password/)).toHaveValue("")
  })

  it("sets up an authenticator app from Settings and shows the recovery codes once", async () => {
    history.replaceState(null, "", "/#settings")
    mocks.session.mockResolvedValue(session)
    mocks.twoFactorStatus.mockResolvedValueOnce(off).mockResolvedValue(on)
    mocks.setupTotp.mockResolvedValue({ secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/LightBWS:admin?secret=JBSWY3DPEHPK3PXP&issuer=LightBWS" })
    mocks.confirmTotp.mockResolvedValue({ recoveryCodes: ["aaaa-bbbb-cccc", "dddd-eeee-ffff"] })
    render(<Providers><App /></Providers>)

    await userEvent.click(await screen.findByRole("button", { name: "Set up authenticator app" }))
    const dialog = await screen.findByRole("dialog")
    await userEvent.type(within(dialog).getByLabelText(/^Current password/), "password")
    await userEvent.click(within(dialog).getByRole("button", { name: "Continue" }))
    expect(await within(dialog).findByRole("img", { name: "QR code for your authenticator app" })).toBeInTheDocument()
    expect(within(dialog).getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument()
    await userEvent.type(within(dialog).getByLabelText(/^Authenticator code/), "123456")
    await userEvent.click(within(dialog).getByRole("button", { name: "Verify" }))
    expect(await within(dialog).findByText("dddd-eeee-ffff")).toBeInTheDocument()
    expect(mocks.setupTotp).toHaveBeenCalledWith("password")
    expect(mocks.confirmTotp).toHaveBeenCalledWith("123456")

    await userEvent.click(within(dialog).getByRole("button", { name: "I have saved these codes" }))
    expect(await screen.findByRole("button", { name: "Generate new recovery codes" })).toBeInTheDocument()
    expect(screen.queryByText("dddd-eeee-ffff")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Set up authenticator app" })).not.toBeInTheDocument()
  })

  it("hides turning it off when policy requires it, and asks for a code to change the password", async () => {
    history.replaceState(null, "", "/#settings")
    mocks.session.mockResolvedValue(session)
    mocks.twoFactorStatus.mockResolvedValue({ ...on, required: true })
    mocks.changePassword.mockRejectedValueOnce(new ApiError(403, "INVALID_CREDENTIALS")).mockResolvedValue(undefined)
    render(<Providers><App /></Providers>)

    await userEvent.click(await screen.findByRole("button", { name: "Change password" }))
    expect(screen.queryByRole("button", { name: "Turn off" })).not.toBeInTheDocument()
    const dialog = await screen.findByRole("dialog")
    await userEvent.type(within(dialog).getByLabelText(/^Current password/), "old-password")
    await userEvent.type(within(dialog).getByLabelText(/^New password/), "new-password")
    await userEvent.type(within(dialog).getByLabelText(/^Authenticator code/), "111111")
    await userEvent.click(within(dialog).getByRole("button", { name: "Save" }))
    expect(await within(dialog).findByText("The password or code is incorrect.")).toBeInTheDocument()
    await userEvent.type(within(dialog).getByLabelText(/^Authenticator code/), "222222")
    await userEvent.click(within(dialog).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(mocks.changePassword).toHaveBeenLastCalledWith({ currentPassword: "old-password", newPassword: "new-password", code: "222222" })
  })

  it("holds a user at setup when policy requires enrolment", async () => {
    mocks.session.mockResolvedValueOnce({ ...session, twoFactorEnrollmentRequired: true }).mockResolvedValue(session)
    mocks.setupTotp.mockResolvedValue({ secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/LightBWS:admin?secret=JBSWY3DPEHPK3PXP" })
    mocks.confirmTotp.mockResolvedValue({ recoveryCodes: ["aaaa-bbbb-cccc"] })
    render(<Providers><App /></Providers>)

    expect(await screen.findByRole("heading", { level: 1, name: "Set up two-factor authentication" })).toBeInTheDocument()
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument()
    await userEvent.type(screen.getByLabelText(/^Current password/), "password")
    await userEvent.click(screen.getByRole("button", { name: "Continue" }))
    await userEvent.type(await screen.findByLabelText(/^Authenticator code/), "123456")
    await userEvent.click(screen.getByRole("button", { name: "Verify" }))
    await userEvent.click(await screen.findByRole("button", { name: "I have saved these codes" }))
    expect(await screen.findByRole("navigation")).toBeInTheDocument()
  })

  it("lets an administrator reset another user's second factor", async () => {
    history.replaceState(null, "", "/#users")
    mocks.session.mockResolvedValue(session)
    mocks.users.mockResolvedValue([
      { ...session.user, twoFactorEnabled: true },
      { ...session.user, id: "user-2", username: "sam", displayName: "Sam", role: "user", twoFactorEnabled: true },
    ])
    mocks.resetUserTwoFactor.mockResolvedValue(undefined)
    render(<Providers><App /></Providers>)

    const buttons = await screen.findAllByRole("button", { name: "Reset 2FA" })
    expect(buttons).toHaveLength(1)
    await userEvent.click(buttons[0])
    await userEvent.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Reset 2FA" }))
    await waitFor(() => expect(mocks.resetUserTwoFactor).toHaveBeenCalledWith("user-2"))
  })
})
