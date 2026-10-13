import re

with open('/www/wwwroot/mhpanel/templates/partials/styles.html', 'r') as f:
    css = f.read()

# Replace :root variables
css = re.sub(r'--bg-base: #060813;', '--bg-base: #f9fafb;', css)
css = re.sub(r'--bg-surface: rgba\(14, 18, 36, 0.45\);', '--bg-surface: rgba(255, 255, 255, 0.9);', css)
css = re.sub(r'--bg-surface-opaque: #0b0f22;', '--bg-surface-opaque: #ffffff;', css)
css = re.sub(r'--border-glow: rgba\(127, 0, 255, 0.15\);', '--border-glow: rgba(0, 0, 0, 0.05);', css)
css = re.sub(r'--text-main: #f3f4f6;', '--text-main: #111827;', css)
css = re.sub(r'--text-muted: #9ca3af;', '--text-muted: #6b7280;', css)
css = re.sub(r'--text-dim: #6b7280;', '--text-dim: #9ca3af;', css)

# Body gradients
css = re.sub(r'rgba\(139, 92, 246, 0.08\)', 'rgba(99, 102, 241, 0.05)', css)
css = re.sub(r'rgba\(6, 182, 212, 0.08\)', 'rgba(14, 165, 233, 0.05)', css)

# Replace common white/transparent text colors for inputs and backgrounds
css = re.sub(r'background: rgba\(255, 255, 255, 0.04\);', 'background: #ffffff;', css)
css = re.sub(r'background: rgba\(255, 255, 255, 0.07\);', 'background: #f3f4f6;', css)
css = re.sub(r'border: 1px solid rgba\(255, 255, 255, 0.1\);', 'border: 1px solid rgba(0, 0, 0, 0.1);', css)
css = re.sub(r'border: 1px solid rgba\(255, 255, 255, 0.07\);', 'border: 1px solid rgba(0, 0, 0, 0.05);', css)
css = re.sub(r'border-bottom: 1px solid rgba\(255, 255, 255, 0.05\);', 'border-bottom: 1px solid rgba(0, 0, 0, 0.05);', css)
css = re.sub(r'border: 1px solid rgba\(255, 255, 255, 0.05\);', 'border: 1px solid rgba(0, 0, 0, 0.05);', css)
css = re.sub(r'border-bottom: 1px solid rgba\(255, 255, 255, 0.08\);', 'border-bottom: 1px solid rgba(0, 0, 0, 0.08);', css)
css = re.sub(r'border: 1px solid rgba\(255, 255, 255, 0.08\);', 'border: 1px solid rgba(0, 0, 0, 0.08);', css)

# App header background
css = re.sub(r'background: rgba\(6, 8, 19, 0.8\);', 'background: rgba(255, 255, 255, 0.85);', css)
css = re.sub(r'background: rgba\(6, 8, 19, 0.85\);', 'background: rgba(255, 255, 255, 0.85);', css)

# Buttons and headers that used to be dark
css = re.sub(r'background: rgba\(255, 255, 255, 0.05\);', 'background: #f3f4f6;', css)
css = re.sub(r'background: rgba\(255, 255, 255, 0.02\);', 'background: #f9fafb;', css)
css = re.sub(r'background: rgba\(255, 255, 255, 0.03\);', 'background: #ffffff;', css)
css = re.sub(r'background: rgba\(255, 255, 255, 0.1\);', 'background: #e5e7eb;', css)

# Replace `#fff` text with `var(--text-main)` in specific places where background is now white
css = re.sub(r'color: #fff;', 'color: var(--text-main);', css)

# The login title uses a gradient text
css = re.sub(r'background: linear-gradient\(to right, #fff, var\(--text-muted\)\);', 'background: linear-gradient(to right, #111827, var(--text-muted));', css)

# Terminal / Console background
css = re.sub(r'background: #020205;', 'background: #f3f4f6;', css)
css = re.sub(r'color: #00ff66;', 'color: #059669;', css)

with open('/www/wwwroot/mhpanel/templates/partials/styles.html', 'w') as f:
    f.write(css)

print("Theme updated successfully.")
