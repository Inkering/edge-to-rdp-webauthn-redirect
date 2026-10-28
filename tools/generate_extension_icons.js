// Original vector artwork; run from the repository root with gjs.
"use strict";
const Cairo = imports.cairo;
const GLib = imports.gi.GLib;

function render(size, path) {
  const surface = new Cairo.ImageSurface(Cairo.Format.ARGB32, size, size);
  const cr = new Cairo.Context(surface);
  cr.scale(size / 128, size / 128);
  cr.setSourceRGB(0.06, 0.10, 0.18);
  const radius = 24;
  for (const [x, y, angle] of [
    [104, 24, -Math.PI / 2], [104, 104, 0],
    [24, 104, Math.PI / 2], [24, 24, Math.PI],
  ]) cr.arc(x, y, radius, angle, angle + Math.PI / 2);
  cr.closePath();
  cr.fill();

  cr.setLineWidth(8);
  cr.setLineCap(Cairo.LineCap.ROUND);
  cr.setLineJoin(Cairo.LineJoin.ROUND);
  cr.setSourceRGB(0.33, 0.69, 1);
  cr.moveTo(27, 30);
  cr.lineTo(99, 30);
  cr.moveTo(88, 19);
  cr.lineTo(99, 30);
  cr.lineTo(88, 41);
  cr.stroke();

  cr.setSourceRGB(0.29, 0.85, 0.64);
  cr.moveTo(101, 98);
  cr.lineTo(29, 98);
  cr.moveTo(40, 87);
  cr.lineTo(29, 98);
  cr.lineTo(40, 109);
  cr.stroke();

  cr.setSourceRGB(1, 1, 1);
  cr.arc(43, 64, 12, 0, 2 * Math.PI);
  cr.stroke();
  cr.moveTo(55, 64);
  cr.lineTo(96, 64);
  cr.lineTo(96, 75);
  cr.moveTo(82, 64);
  cr.lineTo(82, 75);
  cr.stroke();
  surface.writeToPNG(path);
}

for (const directory of ["extension/icons", "publishing"]) {
  if (GLib.mkdir_with_parents(directory, 0o755) !== 0)
    throw new Error(`Cannot create ${directory}`);
}
for (const size of [16, 32, 48, 128])
  render(size, `extension/icons/icon${size}.png`);
render(300, "publishing/logo300.png");
