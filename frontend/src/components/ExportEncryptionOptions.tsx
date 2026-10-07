import { useState } from "react";

export function useExportEncryption() {
  const [encrypt, setEncrypt] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const options = () => {
    if (!encrypt) return {};
    if (!password.trim() || !confirm.trim()) throw new Error("비밀번호와 비밀번호 확인을 입력하세요.");
    if (password !== confirm) throw new Error("비밀번호가 일치하지 않습니다.");
    return { encrypt: true, password };
  };
  const clear = () => { setPassword(""); setConfirm(""); };
  return { encrypt, password, confirm, setEncrypt, setPassword, setConfirm, options, clear };
}

type Props = { value: ReturnType<typeof useExportEncryption>; disabled: boolean };
export function ExportEncryptionOptions({ value, disabled }: Props) {
  return <div className="export-encryption"><label><input type="checkbox" checked={value.encrypt} disabled={disabled} onChange={event => { value.setEncrypt(event.target.checked); value.clear(); }} />파일 암호화</label>{value.encrypt && <><label>비밀번호<input type="password" autoComplete="new-password" value={value.password} disabled={disabled} onChange={event => value.setPassword(event.target.value)} /></label><label>비밀번호 확인<input type="password" autoComplete="new-password" value={value.confirm} disabled={disabled} onChange={event => value.setConfirm(event.target.value)} /></label></>}</div>;
}
