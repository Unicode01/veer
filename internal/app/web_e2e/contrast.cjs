// Inspect rendered text, including inherited/transparent backgrounds in plugin frames.
// Disabled controls, hidden nodes and decorative content have no contrast requirement.
async function contrastIssues(scope) {
  return scope.evaluate(() => {
    const rgb = (value) => {
      const canvas = document.createElement('canvas').getContext('2d');
      canvas.fillStyle = value;
      canvas.fillRect(0, 0, 1, 1);
      const [r, g, b, a] = canvas.getImageData(0, 0, 1, 1).data;
      return [r, g, b, a / 255];
    };
    const blend = (front, back) => front.slice(0, 3).map((c, i) => c * front[3] + back[i] * (1 - front[3])).concat(1);
    const luminance = (color) => color.slice(0, 3).map((c) => c / 255).map((c) => c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
    const root = getComputedStyle(document.documentElement);
    const backdrop = rgb(root.getPropertyValue('--veer-surface').trim() || root.getPropertyValue('--surface').trim() || 'white');
    const issues = [];
    document.querySelectorAll('body *').forEach((el) => {
      const style = getComputedStyle(el);
      if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) || el.closest('[inert], [disabled], [aria-hidden="true"], option, svg')) return;
      const text = Array.from(el.childNodes).filter((n) => n.nodeType === Node.TEXT_NODE).map((n) => n.textContent).join('').trim();
      const input = el.matches('input:not([type=checkbox]):not([type=radio]), textarea, select');
      if (!text && !input) return;
      const ancestors = [];
      for (let parent = el; parent; parent = parent.parentElement) ancestors.unshift(parent);
      const background = ancestors.reduce((color, parent) => blend(rgb(getComputedStyle(parent).backgroundColor), color), backdrop);
      const color = rgb(input && !el.value && el.placeholder ? getComputedStyle(el, '::placeholder').color : style.color);
      color[3] *= ancestors.reduce((opacity, parent) => opacity * Number(getComputedStyle(parent).opacity), 1);
      const foreground = blend(color, background);
      const a = luminance(foreground), b = luminance(background);
      const ratio = (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
      const large = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && parseInt(style.fontWeight, 10) >= 700);
      if (ratio < (large ? 3 : 4.5)) issues.push({ element: el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + '.' + String(el.className).split(' ').join('.'), text: (text || el.value || el.placeholder || '').slice(0, 70), ratio: Number(ratio.toFixed(2)), color: style.color, background: background.slice(0, 3) });
    });
    return issues;
  });
}

async function brightDarkSurfaces(scope) {
  return scope.evaluate(() => Array.from(document.querySelectorAll('input:not([type=checkbox]):not([type=radio]), textarea, select, section, .veer-card, .vpn-panel, .vpn-outlet, [role=menu], .modal-content, .resource-drawer-panel')).filter((el) => {
    if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
    const values = getComputedStyle(el).backgroundColor.match(/[\d.]+/g).map(Number);
    return (values[3] === undefined || values[3] > .5) && Math.min(...values.slice(0, 3)) > 150;
  }).map((el) => el.tagName.toLowerCase() + '#' + el.id + '.' + el.className));
}

module.exports = { contrastIssues, brightDarkSurfaces };
