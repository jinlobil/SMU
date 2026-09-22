import {useEffect,useRef,useState} from "react";

type MonthPickerProps={value:string;onChange:(value:string)=>void};
const parse=(value:string)=>{const [year,month]=value.split("-").map(Number);return {year,month}};
export function MonthPicker({value,onChange}:MonthPickerProps){
  const selected=parse(value),[open,setOpen]=useState(false),[year,setYear]=useState(selected.year),root=useRef<HTMLDivElement>(null),today=new Date();
  useEffect(()=>setYear(selected.year),[selected.year]);
  useEffect(()=>{const close=(event:MouseEvent)=>{if(!root.current?.contains(event.target as Node))setOpen(false)};document.addEventListener("mousedown",close);return()=>document.removeEventListener("mousedown",close)},[]);
  const choose=(month:number)=>{onChange(`${year}-${String(month).padStart(2,"0")}`);setOpen(false)};
  return <div className="month-picker" ref={root}><button type="button" className="month-picker-trigger" aria-haspopup="dialog" aria-expanded={open} onClick={()=>setOpen(!open)}><span>{value}</span><i>▾</i></button>{open&&<section className="context-menu month-picker-popover" role="dialog" aria-label="월 선택"><header><button type="button" aria-label="이전 연도" onClick={()=>setYear(year-1)}>‹</button><b>{year}년</b><button type="button" aria-label="다음 연도" onClick={()=>setYear(year+1)}>›</button></header><div>{Array.from({length:12},(_,index)=>index+1).map(month=><button type="button" key={month} className={`${selected.year===year&&selected.month===month?"selected ":""}${today.getFullYear()===year&&today.getMonth()+1===month?"current":""}`.trim()} onClick={()=>choose(month)}>{month}월</button>)}</div></section>}</div>;
}
