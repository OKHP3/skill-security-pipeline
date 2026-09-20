import type { SVGProps } from 'react';

type Props = SVGProps<SVGSVGElement> & { name: 'arrow' | 'external' | 'github' | 'copy' | 'check' | 'menu' | 'close' | 'shield' | 'code' | 'layers' };
const paths = {
  arrow: <><path d="M4 12h16M14 6l6 6-6 6" /></>,
  external: <><path d="M14 4h6v6M20 4 10 14M10 4H4v16h16v-6" /></>,
  github: <><path d="M9 19c-4 1-4-2-6-2m12 5v-4a3.5 3.5 0 0 0-1-3c3 0 6-1 6-6a4.5 4.5 0 0 0-1-3 4 4 0 0 0 0-3s-1 0-3 1a11 11 0 0 0-6 0C8 3 7 3 7 3a4 4 0 0 0 0 3 4.5 4.5 0 0 0-1 3c0 5 3 6 6 6a3.5 3.5 0 0 0-1 3v4" /></>,
  copy: <><rect x="8" y="8" width="12" height="13" rx="1" /><path d="M16 8V3H3v13h5" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  close: <path d="m6 6 12 12M18 6 6 18" />,
  shield: <><path d="m12 2 8 3v7c0 5-8 10-8 10S4 17 4 12V5Z" /><path d="m13 6-3 6 4 1-3 5" /></>,
  code: <><path d="m8 6-6 6 6 6m8-12 6 6-6 6M14 3l-4 18" /></>,
  layers: <><path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 17l10 5 10-5" /></>,
};
export function Icon({ name, ...props }: Props) {
  return <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>{paths[name]}</svg>;
}

export function ForgedShield() {
  return <svg className="forged-shield" viewBox="0 0 460 470" fill="none" aria-hidden="true">
    <defs>
      <pattern id="shield-hatch" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(35)"><path d="M0 0v8" stroke="#e6a03c" strokeOpacity=".08" strokeWidth="1" /></pattern>
      <linearGradient id="shield-metal" x1="114" x2="325" y1="82" y2="380" gradientUnits="userSpaceOnUse"><stop stopColor="#385148"/><stop offset="1" stopColor="#152d28"/></linearGradient>
    </defs>
    <path d="M230 20v423M20 211h420" stroke="#80705e" strokeOpacity=".25" strokeDasharray="3 8" />
    <circle cx="230" cy="213" r="183" stroke="#80705e" strokeOpacity=".2" />
    <circle cx="230" cy="213" r="157" stroke="#80705e" strokeOpacity=".15" strokeDasharray="2 5" />
    <path d="m230 50 142 54v120c0 91-87 154-142 185-55-31-142-94-142-185V104Z" fill="url(#shield-metal)" stroke="#c46a2c" strokeWidth="2" />
    <path d="m230 67 127 48v109c0 80-75 139-127 168-52-29-127-88-127-168V115Z" fill="url(#shield-hatch)" stroke="#8a806e" strokeOpacity=".5" />
    <path d="m230 90 107 41v92c0 66-60 119-107 148-47-29-107-82-107-148v-92Z" stroke="#e6a03c" strokeOpacity=".22" />
    <path d="m243 102-25 95 39 17-47 111" stroke="#e6a03c" strokeWidth="4" strokeLinejoin="miter" />
    <path d="m234 215 23-1-17 40" stroke="#f6f2ee" strokeWidth="2" />
    <path d="M87 103 54 78H23M369 222h54M258 325l73 90h83" stroke="#c46a2c" strokeWidth="1" />
    <circle cx="87" cy="103" r="3" fill="#e6a03c"/><circle cx="369" cy="222" r="3" fill="#e6a03c"/><circle cx="258" cy="325" r="3" fill="#e6a03c"/>
    {[ [118, 124], [342, 124], [118, 214], [342, 214], [169, 327], [291, 327] ].map(([cx,cy]) => <g key={`${cx}-${cy}`}><circle cx={cx} cy={cy} r="4" fill="#2a2320" stroke="#a88859"/><path d={`M${cx-2} ${cy}h4`} stroke="#a88859"/></g>)}
    <path d="M34 40h19M43 31v19M402 363h19M411 354v19" stroke="#e6a03c" strokeOpacity=".6"/>
    <text x="23" y="67" fill="#b9aa98" fontSize="9" fontFamily="'JetBrains Mono', monospace" letterSpacing="1">INSPECT THE SEAMS</text>
    <text x="230" y="452" fill="#b9aa98" fontSize="10" textAnchor="middle" fontFamily="'JetBrains Mono', monospace" letterSpacing="3">BUILT TO BE EXAMINED</text>
  </svg>;
}
