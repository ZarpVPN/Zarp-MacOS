import SwiftUI

/// Apply the frame and background to Menu itself because AppKit flattens its label.
struct DarkMenu<Content: View>: View {
    let title: String
    let width: CGFloat
    @ViewBuilder var content: () -> Content

    var body: some View {
        Menu(content: content) { Text(title).lineLimit(1) }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .font(Theme.font(11.5))
            .foregroundColor(Theme.text)
            .tint(Theme.text)
            .padding(.leading, 10)
            .padding(.trailing, 28)
            .frame(width: width, height: 32)
            .background(RoundedRectangle(cornerRadius: 8).fill(Theme.panel))
            .overlay(alignment: .trailing) {
                Image(systemName: "chevron.down")
                    .font(.system(size: 9)).foregroundColor(Theme.textDim)
                    .padding(.trailing, 12).allowsHitTesting(false)
            }
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.border, lineWidth: 1))
    }
}
