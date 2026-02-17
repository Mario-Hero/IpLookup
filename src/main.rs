use anyhow::{Context, Result};
use async_recursion::async_recursion;
use clap::Parser;
use dashmap::DashMap;
use hickory_resolver::config::NameServerConfigGroup;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{Resolver, config::ResolverConfig};
use once_cell::sync::Lazy;
use reqwest;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::{
    fs::File,
    io,
    io::{BufRead, BufReader},
    net::IpAddr,
};
use tokio::process::Command;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    /// 域名
    domain: Option<String>,

    /// DNS IP列表，逗号分隔
    dns_list: Option<String>,

    /// DNS服务器文件路径 (每行一个IP)
    #[arg(short = 'd', long = "dns_file")]
    dns_file: Option<String>,
}

static PING_CACHE: Lazy<DashMap<String, bool>> = Lazy::new(DashMap::new);

fn read_dns_from_file(path: &str) -> Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

async fn ping(ip: &str) -> bool {
    #[cfg(target_os = "windows")]
    let args = ["-n", "1", ip];
    #[cfg(not(target_os = "windows"))]
    let args = ["-c", "1", ip];

    let output = Command::new("ping").args(&args).output().await;

    output.map_or(false, |output| output.status.success())
}

async fn ping_with_cache(ip: &str) -> bool {
    if let Some(res) = PING_CACHE.get(ip) {
        return *res;
    }
    // 先占用，防止重复ping
    PING_CACHE.insert(ip.to_string(), false);
    let res = ping(ip).await;
    PING_CACHE.entry(ip.to_string()).and_modify(|v| *v = true);
    println!("{:12} ping{}通", ip, if res { "" } else { "不" });
    res
}

async fn nslookup(domain: &str, dns_ip: &str) -> Result<IpAddr, ()> {
    let dns_ip = dns_ip.parse::<IpAddr>().map_err(|_| ())?;
    let ns_config = NameServerConfigGroup::from_ips_clear(&[dns_ip], 53, true);
    let resolver_config = ResolverConfig::from_parts(None, vec![], ns_config);
    let resolver =
        Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default()).build();
    let response = resolver
        .lookup_ip(domain)
        .await
        .context("failed to lookup ip")
        .map_err(|_| ())?;
    for address in response.iter() {
        println!("{} {}   [dns:{}]", domain, address, dns_ip);
        if address.to_string() == "127.0.0.1" {
            continue;
        }
        if ping_with_cache(address.to_string().as_str()).await {
            return Ok(address);
        }
    }
    Err(())
}

async fn any_nslookup(domain: &str, servers: &Vec<String>) -> Result<IpAddr, ()> {
    use futures::future::select_ok;
    let futures: Vec<Pin<Box<dyn Future<Output = Result<IpAddr, ()>> + Send>>> = servers
        .iter()
        .map(|dns| {
            // 先是 Pin<Box<impl Future...>>
            let fut = nslookup(&domain, &dns);
            // 明确转换成 Trait Object
            Pin::from(Box::new(fut) as Box<dyn Future<Output = Result<IpAddr, ()>> + Send>)
        })
        .collect();

    let (ok_ip, _) = select_ok(futures).await?;
    Ok(ok_ip)
}

fn hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        return PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
    }
    #[cfg(target_os = "linux")]
    {
        return PathBuf::from("/etc/hosts");
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    compile_error!("Unsupported OS for hosts_path");
}

fn already_exists(ip: &IpAddr, domain: &str) -> bool {
    if let Ok(file) = File::open(hosts_path()) {
        let reader = BufReader::new(file);
        let domain_with_space = " ".to_string() + &*domain.to_string();
        for line in reader.lines().filter_map(|l| l.ok()) {
            if line.trim().starts_with('#') {
                continue;
            }
            if line.contains(domain_with_space.as_str()) {
                if line.starts_with(ip.to_string().as_str()) {
                    println!("hosts 文件中已存在该记录: {}", line);
                } else {
                    println!("hosts 文件中已存在该记录，但IP不同: {}", line);
                }
                return true;
            }
        }
    }
    false
}

async fn flush_dns() -> Result<(), String> {
    let output = Command::new("ipconfig")
        .arg("/flushdns")
        .output()
        .await
        .expect("failed to execute process");

    if output.status.success() {
        println!("DNS 刷新成功！");
        Ok(())
    } else {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        Err(format!("DNS 刷新失败: {}", error_msg))
    }
}

#[async_recursion]
async fn nslookup_and_add(domain: &str, dns_servers: &Vec<String>, is_main_page: bool) -> bool {
    if ping_with_cache(domain).await {
        if is_main_page {
            return access_url_in_web(domain, dns_servers).await;
        }
        return true;
    }
    match any_nslookup(domain, dns_servers).await {
        Ok(ip) => {
            println!("{} 的IP是: {}", domain, ip);
            // 检查是否已存在
            if already_exists(&ip, &*domain) {
                return false;
            }

            // 打开文件，追加写入
            let mut file = match OpenOptions::new().append(true).open(&hosts_path()) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("打开hosts文件失败: {}", e);
                    return false;
                }
            };

            let line = format!("{} {}\n", ip, domain);
            if let Err(e) = file.write_all(line.as_bytes()) {
                eprintln!("写入hosts失败: {}", e);
            } else {
                println!("已写入: {} {}", ip, domain);
                #[cfg(target_os = "windows")]
                flush_dns().await.unwrap();
                if !is_main_page {
                    return true;
                }
                return access_url_in_web(&domain, dns_servers).await;
            }
        }
        Err(()) => eprintln!("DNS 查询失败！"),
    }
    false
}

async fn access_url_in_web(domain: &str, dns_servers: &Vec<String>) -> bool {
    match url_in_web(domain).await {
        Ok(url_set) => {
            for url in url_set {
                if !ping_with_cache(url.as_str()).await {
                    nslookup_and_add(url.as_str(), dns_servers, false).await;
                }
            }
        }
        Err(e) => {
            eprintln!("网站访问错误: {}", e);
            return false;
        }
    }
    true
}

fn strip_url(s: String) -> String {
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .or_else(|| s.strip_prefix("//"))
        .unwrap_or(s.as_str())
        .trim();
    s.split('/').next().unwrap_or(s).to_string()
}

async fn url_in_web(web: &str) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
    let correct_web;
    if !(web.starts_with("http://") || web.starts_with("https://")) {
        correct_web = "https://".to_string() + web;
    } else {
        correct_web = web.parse()?;
    }
    println!("访问网站: {}", correct_web);
    // 发送GET请求获取网页内容
    let body = reqwest::get(correct_web).await?.text().await?;

    // 解析HTML
    let document = Html::parse_document(&body);

    let mut set = HashSet::new();

    let selector = Selector::parse("link").unwrap();
    for element in document.select(&selector) {
        // 获取每个a标签的href属性
        if let Some(href) = element.value().attr("href") {
            if !href.is_empty() {
                set.insert(strip_url(href.to_string()));
            }
        }
    }

    let img_selector = Selector::parse("img").unwrap();
    for element in document.select(&img_selector) {
        if let Some(src) = element.value().attr("src") {
            if !src.is_empty() {
                set.insert(strip_url(src.to_string()));
            }
        }
    }
    println!("网站包含的url列表: {:?}", set);
    Ok(set)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(raw_domain) = args.domain {
        let domain = strip_url(raw_domain);
        let dns_servers;
        // 优先使用文件，否则用参数
        if let Some(ref path) = args.dns_file {
            dns_servers = read_dns_from_file(path)?;
        } else if let Some(dns_list) = args.dns_list {
            dns_servers = dns_list
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else {
            dns_servers = read_dns_from_file("./dns")?;
        }
        nslookup_and_add(&domain, &dns_servers, true).await;
    } else {
        let dns_servers = read_dns_from_file("./dns")?;
        loop {
            println!("请输入域名:");
            let mut raw_domain = String::new(); // 创建一个可变字符串用于存储输入
            io::stdin()
                .read_line(&mut raw_domain) // 读取用户输入
                .expect("域名输入错误"); // 错误处理
            let domain = strip_url(raw_domain);
            if domain == "" {
                continue;
            }
            nslookup_and_add(&domain, &dns_servers, true).await;
        }
    }
    Ok(())
}
