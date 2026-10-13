import SwiftUI

struct ContentView: View {
    @StateObject private var model = AuthViewModel()
    @Environment(\.scenePhase) private var scenePhase
    @State private var showResetConfirmation = false

    var body: some View {
        NavigationStack {
            Form {
                if !model.enrolled {
                    Section("Pair this iPhone") {
                        TextField("https://your-server.ngrok-free.app", text: $model.serverURL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                        TextField("Device name", text: $model.deviceName)
                        SecureField("One-time pairing token", text: $model.pairingToken)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button {
                            Task { await model.enroll() }
                        } label: {
                            HStack {
                                Text("Pair with Secure Enclave")
                                if model.busy { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(model.busy || model.pairingToken.isEmpty || model.serverURL.isEmpty)
                    }
                    Section {
                        Text("Generate a pairing token on your Go server. A device with Face ID or Touch ID and a passcode is required. The private key is non-exportable.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Section("Device") {
                        LabeledContent("Status", value: "Paired")
                        Text("Device ID: \(model.deviceID)")
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                        Button("Check for requests") {
                            Task { await model.refresh() }
                        }
                    }
                    Section("Pending authorizations") {
                        if model.pending.isEmpty {
                            ContentUnavailableView(
                                "No pending requests",
                                systemImage: "checkmark.shield",
                                description: Text("New server requests appear here while the app is open.")
                            )
                        }
                        ForEach(model.pending) { request in
                            VStack(alignment: .leading, spacing: 12) {
                                Text(request.action).font(.headline)
                                Text("Request \(request.id.prefix(12))…")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                HStack {
                                    Button("Reject") {
                                        Task { await model.deny(request) }
                                    }
                                    .buttonStyle(.bordered)
                                    .disabled(model.busyRequestID != nil)
                                    Spacer()
                                    Button("Approve with Face ID") {
                                        Task { await model.approve(request) }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(model.busyRequestID != nil)
                                }
                            }
                            .padding(.vertical, 6)
                        }
                    }
                    Section("Device management") {
                        Button("Forget local pairing", role: .destructive) {
                            showResetConfirmation = true
                        }
                    }
                }
                if !model.message.isEmpty {
                    Section("Latest result") {
                        Text(model.message).font(.footnote).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("BioAuth")
            .task { await model.pollWhileVisible() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { Task { await model.refresh() } }
            }
            .confirmationDialog(
                "Remove local credentials?",
                isPresented: $showResetConfirmation,
                titleVisibility: .visible
            ) {
                Button("Forget this iPhone", role: .destructive) {
                    model.forgetLocalDevice()
                }
            } message: {
                Text("Revoke this device on the server as well. Local reset does not revoke an existing server registration.")
            }
        }
    }
}
