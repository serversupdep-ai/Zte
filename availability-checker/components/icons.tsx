const base = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };

export const Arrow = () => (<svg {...base}><path d="M7 17L17 7M8 7h9v9" /></svg>);
export const Globe = () => (<svg {...base}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18" /></svg>);
export const Phone = () => (<svg {...base}><rect x="7" y="2.5" width="10" height="19" rx="2.5" /><path d="M11 18.5h2" /></svg>);
export const Search = () => (<svg {...base}><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></svg>);
export const Scale = () => (<svg {...base}><path d="M12 3v18M5 21h14M5 7h14M5 7l-3 7a3.5 3.5 0 006 0L5 7zm14 0l-3 7a3.5 3.5 0 006 0l-3-7z" /></svg>);
export const Spark = () => (<svg {...base}><path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z" /></svg>);
export const Copy = () => (<svg {...base}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V6a2 2 0 012-2h9" /></svg>);
