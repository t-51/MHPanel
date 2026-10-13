import re

with open('/www/wwwroot/mhpanel/templates/partials/styles.html', 'r') as f:
    css = f.read()

# Fix text colors for primary colored elements
def fix_color_for_class(class_name, text):
    pattern = r'(\.' + class_name + r'\s*\{[^}]*?color:\s*)var\(--text-main\)(;)'
    return re.sub(pattern, r'\1#ffffff\2', text)

css = fix_color_for_class('btn', css)
css = fix_color_for_class('btn-danger', css)
css = fix_color_for_class('header-logo', css)
css = fix_color_for_class('brand-logo', css)
css = fix_color_for_class('stat-icon-box', css)

with open('/www/wwwroot/mhpanel/templates/partials/styles.html', 'w') as f:
    f.write(css)

print("Colors fixed.")
