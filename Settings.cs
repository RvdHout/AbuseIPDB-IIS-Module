using System;
using System.Web;
using System.Configuration;
using System.IO;
#if DEBUG
using System.Diagnostics;
#endif

namespace AbuseIPDB_IIS_Module
{
    class Settings : ConfigurationSection
    {
        #region "properties"
        /// <summary>
        /// if true, AbuseIPDBModule filtering is enabled
        /// </summary>
        [ConfigurationProperty("Enabled", DefaultValue = "true", IsRequired = false)]
        public bool Enabled
        {
            get
            {
                return (bool)this["Enabled"];
            }
            set
            {
                this["Enabled"] = value;
            }
        }

        /// <summary>
        /// if true, X-AbuseIPDBModule header is added to the response
        /// </summary>
        [ConfigurationProperty("AddHeader", DefaultValue = "true", IsRequired = false)]
        public bool AddHeader
        {
            get
            {
                return (bool)this["AddHeader"];
            }
            set
            {
                this["AddHeader"] = value;
            }
        }

        /// <summary>
        /// Paths to Exclude, comma separated values
        /// </summary>
        [ConfigurationProperty("ExcludePath", DefaultValue = null, IsRequired = false)]
        public string ExcludePath
        {
            get
            {
                return (string)this["ExcludePath"];
            }
            set
            {
                this["ExcludePath"] = value;
            }
        }

        /// <summary>
        /// Extensions to Exclude, comma separated values
        /// </summary>
        [ConfigurationProperty("ExcludeType", DefaultValue = null, IsRequired = false)]
        public string ExcludeType
        {
            get
            {
                return (string)this["ExcludeType"];
            }
            set
            {
                this["ExcludeType"] = value;
            }
        }

        /// <summary>
        /// your own api v2 key from https://www.abuseipdb.com/register
        /// </summary>
        [ConfigurationProperty("ApiKey", DefaultValue = "YOUR_API_KEY", IsRequired = true)]
        [StringValidator(MinLength = 12, MaxLength = 80)]
        public string ApiKey
        {
            get
            {
                return (string)this["ApiKey"];
            }
            set
            {
                this["ApiKey"] = value;
            }
        }

        /// <summary>
        /// TimeOut value for API request
        /// </summary>
        [ConfigurationProperty("TimeOut", DefaultValue = "100000", IsRequired = false)]
        [IntegerValidator(MinValue = 0, MaxValue = 100000)]
        public int TimeOut
        {
            get
            {
                return (int)this["TimeOut"];
            }
            set
            {
                this["TimeOut"] = value;
            }
        }

        /// <summary>
        /// max age for a listed entry, entries below this value will be ignored
        /// </summary>
        [ConfigurationProperty("MaxAge", DefaultValue = "30", IsRequired = false)]
        [IntegerValidator(MinValue = 1, MaxValue = 365)]
        public int MaxAge
        {
            get
            {
                return (int)this["MaxAge"];
            }
            set
            {
                this["MaxAge"] = value;
            }
        }

        /// <summary>
        /// max score for a listed entry
        /// </summary>
        [ConfigurationProperty("MaxScore", DefaultValue = "50", IsRequired = false)]
        [IntegerValidator(MinValue = 0, MaxValue = 100)]
        public int MaxScore
        {
            get
            {
                return (int)this["MaxScore"];
            }
            set
            {
                this["MaxScore"] = value;
            }
        }

        /// <summary>
        /// TTL used for a cached entry; the response from the DNS query for a given
        /// IP will be cached for this amount of time; notice that the TTL is dynamic
        /// so, the TTL will expire "n" seconds after the last time a given cached
        /// element is accessed; a value of 0 disables the caching (not recommended)
        /// </summary>
        [ConfigurationProperty("CacheTTL", DefaultValue = "3600", IsRequired = false)]
        [LongValidator(MinValue = 0)]
        public long CacheTTL
        {
            get
            {
                return (long)this["CacheTTL"];
            }
            set
            {
                this["CacheTTL"] = value;
            }
        }

        /// <summary>
        /// path for the log files, can be relative or even virtual
        /// </summary>
        [ConfigurationProperty("LogPath", DefaultValue = ".", IsRequired = false)]
        [StringValidator(MinLength = 1)]
        public string LogPath
        {
            get
            {
                return NormalizePath((string)this["LogPath"]);
            }
            set
            {
                this["LogPath"] = value;
            }
        }

        /// <summary>
        /// true = enables error logging to file
        /// </summary>
        [ConfigurationProperty("LogErrors", DefaultValue = "false", IsRequired = false)]
        public bool LogErrors
        {
            get
            {
                return (bool)this["LogErrors"];
            }
            set
            {
                this["LogErrors"] = value;
            }
        }

        /// <summary>
        /// true = log blacklisted IPs to logfile
        /// </summary>
        [ConfigurationProperty("LogHits", DefaultValue = "true", IsRequired = false)]
        public bool LogHits
        {
            get
            {
                return (bool)this["LogHits"];
            }
            set
            {
                this["LogHits"] = value;
            }
        }

        /// <summary>
        /// IIS request context for this instance
        /// </summary>
        public HttpContext IISContext { get; set; } = null;

        #endregion

        #region "utilities"
        /// <summary>
        /// normalizes a pathname by expanding whatever environment
        /// variables contained in the given path and then retrieving
        /// the fully qualified pathname; if the class has a valid
        /// HTTP (IIS) context, the path can also be mapped from a
        /// virtual path
        /// </summary>
        /// <param name="pathName">
        /// pathname to be "normalized"
        /// </param>
        /// <returns>
        /// normalized pathname
        /// </returns>
        private string NormalizePath(string pathName)
        {
            if (string.IsNullOrEmpty(pathName)) return pathName;
            string fullPath = null;
            try
            {
                fullPath = Environment.ExpandEnvironmentVariables(pathName);
                if (null != this.IISContext)
                    fullPath = MapVirtPath(fullPath);
                fullPath = Path.GetFullPath(fullPath);
            }
#if DEBUG
            catch (Exception ex)
#else
            catch (Exception)
#endif
            {
#if DEBUG
                TraceMsg("NormalizePath({0}) error {1}", pathName, ex.Message);
#endif
                fullPath = pathName;
            }
            return fullPath;
        }

        /// <summary>
        /// maps an IIS virtual path to a phys path
        /// </summary>
        /// <param name="pathName">
        /// the virtual path to be mapped
        /// </param>
        /// <returns>
        /// the mapped path
        /// </returns>
        private string MapVirtPath(string pathName)
        {
            if (null == this.IISContext) return pathName;
            if (string.IsNullOrEmpty(pathName)) return pathName;
            string mappedPath = null;
            try
            {
                mappedPath = this.IISContext.Server.MapPath(pathName);
            }
#if DEBUG
            catch (Exception ex)
#else
            catch (Exception)
#endif
            {
#if DEBUG
                TraceMsg("MapVirtPath({0}) error {1}", pathName, ex.Message);
#endif
                mappedPath = pathName;
            }
            return mappedPath;
        }
#if DEBUG
        /// <summary>
        /// trace/debug messages
        /// </summary>
        /// <param name="format">format string</param>
        /// <param name="args">message args</param>
        private void TraceMsg(string format, params object[] args)
        {
            string message = string.Format(format, args);
            Trace.WriteLine(message);
        }
#endif
#endregion
    }
}
