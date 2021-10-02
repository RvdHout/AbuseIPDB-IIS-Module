using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Web;
// using System.Web.Caching;
// using System.Reflection;
// using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using RestSharp;
// using RestSharp.Extensions;
using Newtonsoft.Json.Linq;
using NetTools;
using System.IO;
using System.Threading;
using System.Runtime.Caching;
#if DEBUG
using System.Diagnostics;
#endif

namespace AbuseIPDB_IIS_Module
{
    public class AbuseIPDBModule : IHttpModule
    {
        private static readonly string _my_name = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name.ToString();

        private Settings _config = null;            // web.config reader
        private HttpContext _context = null;        // current HTTP context
        private string _hostname = string.Empty;    // hostheader (from request)
        private string _client = string.Empty;      // client IP
        //private readonly Cache _cache = HttpRuntime.Cache;   // system cache
        private readonly MemoryCache _cache = MemoryCache.Default;  // memory cache
        private string _logLine = null;             // bad IP log record

        private bool _disposed = false;              // true - already disposed

        private static readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion); 

        #region "instance"
        // instantiates the class
        public AbuseIPDBModule()
        {
            Initialize();
        }

        // needed by the Http Module
        public void Dispose()
        {
            //Write your custom code here to dispose any objects if needed
            if (this._disposed) return;
            this._disposed = true;
#if DEBUG
            DbgWrite("{0} module disposed.", _my_name);
#endif
        }
        #endregion


        #region "IHttpModule"
        public void Init(HttpApplication context)
        {
            context.BeginRequest += new EventHandler(OnBeginRequestEventHandler);
        }

        private void OnBeginRequestEventHandler(object sender, EventArgs e)
        {
            // config loaded?
            if (this._config == null) return;

            // if filtering is disabled, just return
            if (!this._config.Enabled) return;

            // get a reference to app and context
            HttpApplication application = (HttpApplication)sender;
            this._context = application.Context;
            //this._hostname = this._context.Request.ServerVariables["SERVER_NAME"];
            this._hostname = this._context.Request.Url.Host;
            this._client = this._context.Request.UserHostAddress;

            // sets the request context used for path mapping
            this._config.IISContext = this._context;
            
            // The URI requested by client
            Uri uriAddress = new Uri(this._context.Request.Url.AbsoluteUri);
#if DEBUG
            //DbgWrite("Request URI: {0} URI Segments: {1}", this._context.Request.Url.AbsoluteUri, uriAddress.Segments.Length);
#endif
            //  we don't have to process all requests...
            if (!string.IsNullOrEmpty(this._config.ExcludeType))
            {
                var typeArray = this._config.ExcludeType.Split(',').Select(extension => extension.Trim().ToLower()).Where(extension => !string.IsNullOrEmpty(extension)).ToArray();
                if (uriAddress.Segments.Length > 0 && Path.HasExtension(uriAddress.Segments.Last()))
                {
                    bool exists = Array.Exists(typeArray, element => element.StartsWith(Path.GetExtension(uriAddress.Segments.Last().ToLower())));
                    if (exists)
                    {
#if DEBUG
                        //DbgWrite("Excluded Type found: {0}", Path.GetExtension(uriAddress.Segments.Last().ToLower()));
#endif
                        return;
                    }
                }
            }

            //  we don't have to process all requests...
            if (!string.IsNullOrEmpty(this._config.ExcludePath))
            {
                var pathArray = this._config.ExcludePath.Split(',').Select(path => path.Trim().ToLower()).Where(path => !string.IsNullOrEmpty(path)).ToArray();
                if (uriAddress.Segments.Length > 1 && !string.IsNullOrEmpty(uriAddress.Segments[0]) && !string.IsNullOrEmpty(uriAddress.Segments[1]))
                {
                    bool exists = Array.Exists(pathArray, element => element.StartsWith(string.Format("{0}{1}", uriAddress.Segments[0].ToLower(), uriAddress.Segments[1].ToLower())));
                    if (exists)
                    {
                        
                        // if it is already blocked, we also should block it here
                        var item = CacheGet(this._client);
#if DEBUG
                        //DbgWrite("CacheExists: {0}", item.HasValue);
#endif
                        if (item.HasValue)
                        {
#if DEBUG
                            //DbgWrite("CachedValue: ConfidenceScore {0} for IP Address {1}", item.Value, this._client);
#endif
                            CachePut(this._client, Convert.ToInt32(item.Value), false);
                            try
                            {
                                if (item.Value >= _config.MaxScore)
                                {
                                    try
                                    {
                                        // if the IP was listed, log it after the reject/redirect
                                        if (this._config.LogHits)
                                        {
                                            //LogHit(string.Format("Blocked {0}, Score {1}", this._client, (int)item.Value));
                                            CreateIPrecord(this._client, item.Value);

                                            // if the IP was listed, log it after the reject/redirect
                                            if (!string.IsNullOrEmpty(this._logLine))
                                                LogHit(this._logLine);
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        LogError(string.Format("LogHits::Error: {0}", ex.Message));
                                    }
                                    finally
                                    {
                                        if (this._context.Response.IsClientConnected)
                                        {
                                            this._context.Response.StatusCode = 403;
                                            this._context.Response.SubStatusCode = 6;
                                            this._context.Response.StatusDescription = string.Format("IP Address {0} Rejected by {1}. AbuseIPDB ConfidenceScore {2}.", this._client, _my_name, item.Value);
                                            this._context.Response.SuppressContent = true;
                                            //this._context.ApplicationInstance.CompleteRequest();
                                            this._context.Response.End();
                                        }
                                        else
                                        {
                                            //this._context.ApplicationInstance.CompleteRequest();
                                            this._context.Response.End();
                                        }
                                    }
                                }
                                else
                                {
                                    // just add our header to show we're running
                                    if (this._config.AddHeader)
                                        AddModuleHeader(item.Value);
                                }
                            }
                            catch (System.Threading.ThreadAbortException)
                            {
                                try
                                {
                                    System.Threading.Thread.ResetAbort();
                                }
                                catch (Exception eX)
                                {
                                    LogError(string.Format("BlockEndpoint::Error: msg={0}, trace={1}", eX.Message, eX.StackTrace));
                                }
                            }
                            catch (Exception ex)
                            {
                                LogError(string.Format("BlockEndpoint::Error: {0}", ex.Message));
                            }
                        }
                        else
                        {
#if DEBUG
                            //DbgWrite("Excluded Path found: {0}, Path: {1}", exists, string.Format("{0}{1}", uriAddress.Segments[0], uriAddress.Segments[1]));
#endif
                            return;
                        }
                    }
                }
            }

            if (IsValidIP(this._client))
            {
                try
                {
                    int score = GetConfidenceScore(this._client);
                    if (score >= _config.MaxScore)
                    {
                        try
                        {
                            // if the IP was listed, log it after the reject/redirect
                            if (this._config.LogHits)
                                CreateIPrecord(this._client, score);

                            // if the IP was listed, log it after the reject/redirect
                            if (!string.IsNullOrEmpty(this._logLine))
                                LogHit(this._logLine);
                        }
                        catch (Exception ex)
                        {
                            LogError(string.Format("LogHits::Error: {0}", ex.Message));
                        }
                        finally
                        {
                            if (this._context.Response.IsClientConnected)
                            {
                                this._context.Response.StatusCode = 403;
                                this._context.Response.SubStatusCode = 6;
                                this._context.Response.StatusDescription = string.Format("IP Address {0} Rejected by {1}. AbuseIPDB ConfidenceScore {2}.", this._client, _my_name, score);
                                this._context.Response.SuppressContent = true;
                                //this._context.ApplicationInstance.CompleteRequest();
                                this._context.Response.End();
                            }
                            else
                            {
                                //this._context.ApplicationInstance.CompleteRequest();
                                this._context.Response.End();
                            }
                        }
                    }
                    else 
                    {
                        // just add our header to show we're running
                        if (this._config.AddHeader)
                            AddModuleHeader(score);
                    }
                }
                catch (System.Threading.ThreadAbortException eThreadAbort)
                {
                    try
                    {
#if DEBUG
                        DbgWrite("BlockEndpoint::Error: msg={0}, trace={1}", eThreadAbort.Message, eThreadAbort.StackTrace);
#endif
                        System.Threading.Thread.ResetAbort();
                    }
                    catch (Exception eX)
                    {
                        LogError(string.Format("BlockEndpoint::Error: msg={0}, trace={1}", eX.Message, eX.StackTrace));
                    }
                }
                catch (Exception ex)
                {
                    LogError(string.Format("BlockEndpoint::Error: {0}", ex.Message));
                }
            }
        }
#endregion


#region "privatecode"
        private int GetConfidenceScore(string ipAddress)
        {
            int abuseConfidenceScore = 0;
            var item = CacheGet(ipAddress);
#if DEBUG
            DbgWrite("CacheExists: {0}", item.HasValue);
#endif
            if (item.HasValue)
            {
#if DEBUG
                DbgWrite("CachedValue: ConfidenceScore {0} for IP Address {1}", item.Value, ipAddress);
#endif
                CachePut(ipAddress, Convert.ToInt32(item.Value), false);
                abuseConfidenceScore = Convert.ToInt32(item.Value);
            }
            else
            {
                // make request
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
#if DEBUG
                Stopwatch sw = Stopwatch.StartNew();
#endif
                var client = new RestClient("https://api.abuseipdb.com/api/v2/check");
                var request = new RestRequest(Method.GET)
                {
                    Timeout = _config.TimeOut, // The default value is 100,000 milliseconds (100 seconds).
                    ReadWriteTimeout = _config.TimeOut * 3 // The default value is 300,000 milliseconds (5 minutes).
                };
                request.AddHeader("Key", _config.ApiKey);
                request.AddHeader("Accept", "application/json");
                request.AddParameter("ipAddress", ipAddress);
                request.AddParameter("maxAgeInDays", _config.MaxAge);

                IRestResponse response = client.Execute(request);            
#if DEBUG
                sw.Stop();
                DbgWrite("Request Time {0}, Timeout Value {1}, ResponseStatus: {2}", sw.Elapsed, TimeSpan.FromMilliseconds(request.Timeout), response.ResponseStatus);
#endif
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    try
                    {
                        dynamic json = JObject.Parse(response.Content);
                        abuseConfidenceScore = Convert.ToInt32(json.data.abuseConfidenceScore);
                    }
                    catch (Newtonsoft.Json.JsonException ex)
                    {
                        throw new Exception(ex.Message);
                    }
                    finally
                    {
                        CachePut(ipAddress, abuseConfidenceScore, true);
                    }
                }
                else
                {
                    // put in default value in case abuseipdb.com is not responding, api key is invalid or any other reason why the requet could have failed
                    CachePut(ipAddress, abuseConfidenceScore, true);
                    if (response.ResponseStatus == ResponseStatus.TimedOut)
                        throw new Exception(string.Format("Request {0}", ResponseStatus.TimedOut));
                    else
                        throw new Exception(string.Format("{0}{1}", (int)response.StatusCode, !string.IsNullOrEmpty(response.StatusDescription) ? string.Format(" - {0}", response.StatusDescription) : string.Empty));
                }
            }
            return abuseConfidenceScore;
        }

        // fills up a log record related to "bad IP"
        private void CreateIPrecord(string sIPaddr, int iConfidenceScore)
        {
            try
            {
                string UA = this._context.Request.UserAgent;
                if (string.IsNullOrEmpty(UA)) UA = "none";
                string page = this._context.Request.Url.PathAndQuery;
                if (string.IsNullOrEmpty(page)) page = "none";
                string sBuff = string.Format("{0},{1},{2},{3}", sIPaddr, iConfidenceScore, page, UA);
                this._logLine = sBuff;
                //LogMsg(sBuff); <-- log is written at end of "beginrequest"
            }
            catch (Exception ex)
            {
                LogError(string.Format("createIPrecord::Error: {0}", ex.Message));
            }
        }

        // logs misc messages
        private void LogError(string sMsg)
        {
            try
            {
                if (!this._config.LogErrors) return;
                if (string.IsNullOrEmpty(this._config.LogPath)) return;
                string logName = this._config.LogPath + "\\" + _my_name + "-errors-" + DateTime.UtcNow.ToString("MM") + ".log";
                // datetime,hostheader,message
                string sBuff = string.Format("{0}", sMsg);
                LogMsg(sBuff, logName);
            }
            catch (Exception ex)
            {
                if (ex.GetType() != typeof(UnauthorizedAccessException))
                    LogError("LogError::Error: " + ex.Message);
            }
        }

        // logs a blacklist hit
        private void LogHit(string sMsg)
        {
            try
            {
                if (!this._config.LogHits) return;
                if (string.IsNullOrEmpty(this._config.LogPath)) return;
                string logName = this._config.LogPath + "\\" + _my_name + "-hits-" + DateTime.UtcNow.ToString("MM") + ".log";
                // datetime,hostheader,IPaddress,score,URL,UserAgent
                LogMsg(sMsg, logName);
            }
            catch (Exception ex)
            {
                if (ex.GetType() != typeof(UnauthorizedAccessException))
                    LogError("LogHit::Error: " + ex.Message);
            }
        }

        /// <summary>
        /// logs a message to logfile and to debug; notice that the logfile
        /// is tagged with current month, so we'll have a max of 12 files
        /// at once; older (previous year) logfiles will be automatically
        /// deleted and overwritten as needed; this avoids the need to use
        /// a separate procedure to delete old files; such a procedure may
        /// still be needed in case we want to archive them; in such a case
        /// the procedure may be scheduled on the 1st of each month and
        /// archive the log from the previous month (on 1-1 it will archive
        /// the december log from previous year)
        /// </summary>
        /// <param name="sMsg">
        /// message to log
        /// </param>
        private void LogMsg(string sMsg, string logFileName)
        {
            // always logs to debug
#if DEBUG
            DbgWrite(sMsg);
#endif

            // builds the logfile name and check for file rotation
            string sLogFile = logFileName;
            if (string.IsNullOrEmpty(sLogFile)) return;
            RotateLog(sLogFile);

            // builds the log record buffer
            string sBuff = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffff") + "," + this._hostname;
            if (!string.IsNullOrEmpty(sMsg))
                sBuff += "," + sMsg;
            else
                sBuff += ",----";

            // Set Status to Locked
            _lock.EnterWriteLock();
            try
            {
                // writes to logfile (append)
                using (StreamWriter sw = new StreamWriter(sLogFile, true))
                {
                    sw.WriteLine(sBuff);
                }
            }
#if DEBUG
            catch (LockRecursionException lre)
            {
                LogError(string.Format("LogMsg::Error: file={0}, err={1}", sLogFile, lre.Message));
            }
            catch (Exception ex)
            {
                LogError(string.Format("LogMsg::Error: file={0}, err={1}", sLogFile, ex.Message));
            }
#endif
            finally
            {
                // Release lock
                _lock.ExitWriteLock();
            }
        }

        // rotates (deletes) old logfiles; the code will check if the
        // given file is from "last year" and if so, will delete it so
        // that, writes will recreate it from scratch; notice that the
        // check is only performed on the 1st day of each month
        private void RotateLog(string pathName)
        {
            if (string.IsNullOrEmpty(pathName)) return;
            if (1 != DateTime.UtcNow.Day) return;
            try
            {
                if (File.Exists(pathName))
                {
                    FileInfo fi = new FileInfo(pathName);
                    if (fi.LastWriteTime.Year < DateTime.Now.Year)
                    {
                        // file is old, must be overwritten
                        File.Delete(pathName);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError(string.Format("rotateLog::Error: file={0}, err={1}", pathName, ex.Message));
            }
        }
#if DEBUG
        // writes a line to the debug; to see this log from the compiled app
        // you may use the "DbgView" tool from SysInternals and configure it
        // to only intercept messages containing the "[AbuseIPDBModule]" tag
        private void DbgWrite(string format, params object[] args)
        {
            try
            {
                string msgBuff = string.Format(format, args);
                string outBuff = string.Format("[{0}]: {1}", _my_name, msgBuff);
                Trace.WriteLine(outBuff);
            }
            catch (Exception ex)
            {
                Trace.WriteLine(string.Format("DbgWrite::Error: {0}", ex.Message));
            }
        }
#endif
        // adds an X-Header to the response to show that we're running
        private void AddModuleHeader(int iConfidenceScore)
        {
            try
            {
                string hdrName = string.Format("X-{0}", _my_name);
                string version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
                string hdrValue = string.Format("{0}/{1} (Abuse Confidence: {2}%)", _my_name, version, iConfidenceScore);
                if (this._context.Response.IsClientConnected)
                    this._context.Response.AppendHeader(hdrName, hdrValue);
            }
            catch (Exception ex)
            {
                LogError(string.Format("AddModuleHeader::Error: {0}", ex.Message));
            }
        }

        // true is a valid IP address
        private bool IsValidIP(string sIpAddr)
        {
            if (string.IsNullOrEmpty(sIpAddr)) return false;
            if (!IPAddress.TryParse(sIpAddr, out IPAddress ip)) return false;
            if (!IsPrivateIpAddress(ip)) return true;
            //if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) return true;
            return false;
        }

        /// <summary>
        /// Determines whether or not an IP address lies within a private IP range
        /// </summary>
        /// <param name="ipAddress">The IP address to check</param>
        /// <returns>True if the IP address is a private IP address. False otherwise</returns>
        private static bool IsPrivateIpAddress(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                //IPv4 Loopback
                var rangeIpv4Loopback = IPAddressRange.Parse("127.0.0.0/8");
                //IPv4 Private
                // 10.0.0.0/8 - RFC-1918
                var rangeIpv4Priv1 = IPAddressRange.Parse("10.0.0.0/8");
                // 172.16.0.0/12 - RFC-1918
                var rangeIpv4Priv2 = IPAddressRange.Parse("172.16.0.0/12");
                // 192.168.0.0/16 - RFC-1918
                var rangeIpv4Priv3 = IPAddressRange.Parse("192.168.0.0/16");
                // 192.0.2.0/24 RFC-5735
                var rangeIpv4Priv4 = IPAddressRange.Parse("192.0.2.0/24");
                //IPv4 Link Local 
                // 169.254.0.0/16 - RFC-3927 (APIPA)
                var rangeIpv4Local = IPAddressRange.Parse("169.254.0.0/16");

                //Loopback
                if (rangeIpv4Loopback.Contains(ipAddress))
                    return true;
                //Private
                if (rangeIpv4Priv1.Contains(ipAddress) || rangeIpv4Priv2.Contains(ipAddress) || rangeIpv4Priv3.Contains(ipAddress) || rangeIpv4Priv4.Contains(ipAddress))
                    return true;
                //Link Local
                if (rangeIpv4Local.Contains(ipAddress))
                    return true;
            }
            else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                //IPv6 Loopback
                var rangeIpv6Loopback = IPAddressRange.Parse("::1/128");
                //IPv6 Unique Local
                var rangeIpv6Priv = IPAddressRange.Parse("fc00::/7");
                //IPv6 Link Local
                var rangeIpv6Local = IPAddressRange.Parse("fe80::/10");

                //Loopback
                if (rangeIpv6Loopback.Contains(ipAddress))
                    return true;
                //Unique Local
                if (rangeIpv6Priv.Contains(ipAddress))
                    return true;
                //Link Local
                if (rangeIpv6Local.Contains(ipAddress))
                    return true;
            }

            return false;
        }

        // retrieves an IP from the cache
        private int? CacheGet(string sIP)
        {
            if (0 == this._config.CacheTTL) return null;

            int? iConfidenceScore = null;
            if (_cache != null && _cache.Get(_my_name + "::" + sIP) != null)
            {
/*
#if DEBUG
                // System.Web.Caching
                System.Collections.IDictionaryEnumerator enumerator = _cache.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    string key = (string)enumerator.Key;
                    object value = enumerator.Value;

                    if (key.Contains(_my_name))
                        DbgWrite("Key: {0}, Value: {1}", key, value);
                }
#endif
*/
#if DEBUG
                // System.Runtime.Caching
                var cacheItems = _cache.ToList();
                foreach (KeyValuePair<string, object> a in cacheItems)
                {
                    string key = a.Key;
                    object value = a.Value;
                    if (key.Contains(_my_name))
                        DbgWrite("Key: {0}, Value: {1}", key, value);
                }
#endif

                try
                {
                    iConfidenceScore = (int)_cache[_my_name + "::" + sIP];
                }
                catch (Exception ex)
                {
                    LogError(string.Format("CacheGet::Error: {0}", ex.Message));
                }
            }
            return iConfidenceScore;
        }

        // inserts an IP into the cache
        private void CachePut(string sIP, int iConfidenceScore, bool newEntry)
        {
            // check if cache enabled (TTL > 0)
            if (0 == this._config.CacheTTL) return;
            long lTTL = this._config.CacheTTL;

            // if TTL is "high enough" and IP isn't listed, set TTL=TTL/4
            // for "white" IPs, this avoids issuing too many requests to
            // the AbuseIPDB for "regular" visitors and at the same time
            // to avoid filling up the cache with "good" IPs
            if ((iConfidenceScore < _config.MaxScore) && (lTTL > 300))
                lTTL /= 4;
#if DEBUG
            if (newEntry)
                DbgWrite("Adding IP " + sIP + " with ConfidenceScore " + iConfidenceScore + " to cache (TTL=" + lTTL.ToString() + ")");
            else
                DbgWrite("Updating IP " + sIP + " with ConfidenceScore " + iConfidenceScore + " to cache (TTL=" + lTTL.ToString() + ")");
#endif
            try
            {
                // note: the cache TTL is a dynamic one, this means that a given entry will
                // remain in cache for up to TTL seconds from the last time it was requested
                // this also means that an IP hammering the site will remain in cache for
                // quite a long time ... so sparing load to the AbuseIPDB servers; for further
                // infos see http://msdn.microsoft.com/en-us/library/4y13wyk9.aspx
                
                // System.Web.Caching
                //_cache.Insert(_my_name + "::" + sIP, iConfidenceScore, null, Cache.NoAbsoluteExpiration, TimeSpan.FromSeconds(lTTL));

                // System.Runtime.Caching
                var cacheItem = new CacheItem(_my_name + "::" + sIP, iConfidenceScore);
                var cacheItemPolicy = new CacheItemPolicy
                {
                    SlidingExpiration = TimeSpan.FromSeconds(lTTL),
                };
                _cache.Set(cacheItem, cacheItemPolicy);
            }
            catch (Exception ex)
            {
                LogError(string.Format("CachePut::Error: {0}", ex.Message));
            }
        }

        private void Initialize()
        {
            // link to the config section
            this._config = (Settings)ConfigurationManager.GetSection(_my_name);
            if (this._config != null)
            {
                // log a message to show we were loaded
#if DEBUG
                DbgWrite("{0} module loaded.", _my_name);
#endif
                // dump our defaults (also check if all ok)
                try
                {
#if DEBUG
                    DbgWrite("Enabled.......: {0}", this._config.Enabled);
                    DbgWrite("AddHeader.....: {0}", this._config.AddHeader);
                    DbgWrite("ExcludePath...: {0}", this._config.ExcludePath);
                    DbgWrite("ExcludeType...: {0}", this._config.ExcludeType);
                    DbgWrite("ApiKey........: {0}", this._config.ApiKey);
                    DbgWrite("TimeOut.......: {0}", this._config.TimeOut);
                    DbgWrite("MaxAge........: {0}", this._config.MaxAge);
                    DbgWrite("MaxScore......: {0}", this._config.MaxScore);
                    DbgWrite("CacheTTL......: {0}", this._config.CacheTTL);
                    DbgWrite("LogPath.......: {0}", this._config.LogPath);
                    DbgWrite("LogErrors.....: {0}", this._config.LogErrors);
                    DbgWrite("LogHits.......: {0}", this._config.LogHits);
#endif
                }
                catch (Exception ex)
                {
                    LogError("DumpConfig::Error: " + ex.Message);
                }
            }
        }
#endregion
    }
}