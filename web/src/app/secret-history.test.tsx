import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { Providers } from "./Providers"
import type { Secret, SecretVersion, Session, User } from "./types"

const mocks = vi.hoisted(() => ({
  clearSecretHistory: vi.fn(),
  projects: vi.fn(),
  restoreSecretVersion: vi.fn(),
  secretVersion: vi.fn(),
  secretVersions: vi.fn(),
  secrets: vi.fn(),
  session: vi.fn(),
}))

vi.mock("./api", () => ({
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      public code: string,
      public detail?: string,
    ) {
      super(detail || code)
    }
  },
  api: mocks,
}))

import { App } from "./App"

const member: User = {
  id: "user-2",
  username: "member",
  displayName: "Member",
  role: "user",
  disabled: false,
  createdAt: 1,
  updatedAt: 1,
  lastLoginAt: 1,
}
const session: Session = { csrfToken: "csrf", user: member }
const secret: Secret = {
  id: "secret-1",
  projectId: null,
  key: "DATABASE_URL",
  value: "current-value",
  note: "",
  sdkEncrypted: true,
  deletedAt: null,
  createdAt: 1,
  updatedAt: 2,
  permissions: { read: true, write: true },
}
const version: SecretVersion = {
  version: 1,
  projectId: null,
  actorKind: "user",
  actorId: "user-1",
  actorName: "admin",
  validFrom: 1,
  replacedAt: 2,
  keyChanged: false,
  valueChanged: true,
  noteChanged: false,
}

describe("secret version history", () => {
  afterEach(cleanup)

  beforeEach(() => {
    vi.clearAllMocks()
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
    mocks.session.mockResolvedValue(session)
    mocks.secrets.mockResolvedValue([secret])
    mocks.projects.mockResolvedValue([])
    mocks.secretVersions.mockResolvedValue([version])
    mocks.secretVersion.mockResolvedValue({ version: 1, key: "DATABASE_URL", value: "earlier-value", note: "", validFrom: 1, replacedAt: 2 })
    mocks.restoreSecretVersion.mockResolvedValue({ ...secret, value: "earlier-value" })
  })

  it("lists versions without values, reveals one on request and restores after confirmation", async () => {
    history.replaceState(null, "", "/#secrets")
    render(
      <Providers>
        <App />
      </Providers>,
    )

    await userEvent.click(await screen.findByRole("button", { name: "Version history" }))
    const dialog = await screen.findByRole("dialog", { name: /Version history/ })
    expect(await within(dialog).findByText("#1")).toBeInTheDocument()
    expect(within(dialog).getByText("user admin")).toBeInTheDocument()
    expect(within(dialog).queryByText("earlier-value")).not.toBeInTheDocument()
    expect(mocks.secretVersion).not.toHaveBeenCalled()
    // Clearing history is for administrators only.
    expect(within(dialog).queryByRole("button", { name: "Clear history" })).not.toBeInTheDocument()

    await userEvent.click(within(dialog).getByRole("button", { name: "Show this version" }))
    expect(await within(dialog).findByText("earlier-value")).toBeInTheDocument()
    expect(mocks.secretVersion).toHaveBeenCalledWith("secret-1", 1)

    await userEvent.click(within(dialog).getByRole("button", { name: "Restore this version" }))
    expect(mocks.restoreSecretVersion).not.toHaveBeenCalled()
    await userEvent.click(await screen.findByRole("button", { name: "Restore" }))
    await waitFor(() => expect(mocks.restoreSecretVersion).toHaveBeenCalledWith("secret-1", 1))
  })

  it("hides restore from users who can only read the secret", async () => {
    mocks.secrets.mockResolvedValue([{ ...secret, permissions: { read: true, write: false } }])
    history.replaceState(null, "", "/#secrets")
    render(
      <Providers>
        <App />
      </Providers>,
    )

    await userEvent.click(await screen.findByRole("button", { name: "Version history" }))
    const dialog = await screen.findByRole("dialog", { name: /Version history/ })
    expect(await within(dialog).findByText("#1")).toBeInTheDocument()
    expect(within(dialog).queryByRole("button", { name: "Restore this version" })).not.toBeInTheDocument()
  })
})
