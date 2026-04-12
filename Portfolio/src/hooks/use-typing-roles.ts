"use client";

import { useEffect, useState } from "react";

export function useTypingRoles(roles: readonly string[], typingMs = 70, pauseMs = 1600) {
  const [text, setText] = useState("");
  const [roleIndex, setRoleIndex] = useState(0);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const role = roles[roleIndex % roles.length];
    let timeout: ReturnType<typeof setTimeout>;

    if (!deleting && text.length < role.length) {
      timeout = setTimeout(() => {
        setText(role.slice(0, text.length + 1));
      }, typingMs);
    } else if (!deleting && text.length === role.length) {
      timeout = setTimeout(() => setDeleting(true), pauseMs);
    } else if (deleting && text.length > 0) {
      timeout = setTimeout(() => {
        setText(role.slice(0, text.length - 1));
      }, typingMs / 2);
    } else if (deleting && text.length === 0) {
      setDeleting(false);
      setRoleIndex((i) => (i + 1) % roles.length);
    }

    return () => clearTimeout(timeout);
  }, [text, deleting, roleIndex, roles, typingMs, pauseMs]);

  return text;
}
