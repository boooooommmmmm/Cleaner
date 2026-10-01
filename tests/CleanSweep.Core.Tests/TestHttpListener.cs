using System.Net;

namespace CleanSweep.Core.Tests;

internal static class TestHttpListener
{
    public static (HttpListener Listener, string BaseUrl) Start()
    {
        // CI runners can already be using a randomly selected port. Bind before
        // returning, and retry only listener startup; assertions are never retried.
        for (var attempt = 0; ; attempt++)
        {
            var baseUrl = $"http://127.0.0.1:{Random.Shared.Next(40000, 60000)}";
            var listener = new HttpListener();
            listener.Prefixes.Add(baseUrl + "/");
            try
            {
                listener.Start();
                return (listener, baseUrl);
            }
            catch (HttpListenerException) when (attempt < 19)
            {
                listener.Close();
            }
            catch
            {
                listener.Close();
                throw;
            }
        }
    }
}
