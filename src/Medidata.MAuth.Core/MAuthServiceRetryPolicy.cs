namespace Medidata.MAuth.Core
{
    /// <summary>
    /// Determines the retrying policy with the MAuth server communication.
    /// </summary>
    public enum MAuthServiceRetryPolicy
    {
        /// <summary>
        /// No attempt to retry the service request. The authentication will fail upon the first attempt if it is
        /// not successful.
        /// </summary>
        NoRetry = 0,
        /// <summary>
        /// 1 more attempt to send a request to the MAuth service if the first attempt fails.
        /// </summary>
        Single = 1,
        /// <summary>
        /// 2 more attempts to send a request to the MAuth service if the first attempt fails.
        /// </summary>
        Normal = 2,
        /// <summary>
        /// 9 more attempts to send a request to the MAuth service if the first attempt fails. This setting is not
        /// recommended in production use as it can put more load the the MAuth service.
        /// </summary>
        Agressive = 9
    }
}