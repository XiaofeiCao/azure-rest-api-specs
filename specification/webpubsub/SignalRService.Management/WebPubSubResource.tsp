import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";
import "@typespec/openapi";
import "@typespec/rest";
import "./models.tsp";

using TypeSpec.Rest;
using Azure.ResourceManager;
using TypeSpec.Http;
using TypeSpec.OpenAPI;

namespace Microsoft.SignalRService;
/**
 * A class represent a resource.
 */
#suppress "@azure-tools/typespec-azure-core/no-private-usage" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
#suppress "@azure-tools/typespec-azure-core/no-private-usage" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
#suppress "@azure-tools/typespec-azure-core/composition-over-inheritance" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
@Azure.ResourceManager.Private.armResourceInternal(WebPubSubProperties)
@TypeSpec.Http.Private.includeInapplicableMetadataInPayload(false)
model WebPubSubResource extends Foundations.TrackedResource {
  ...ResourceNameParameter<
    Resource = WebPubSubResource,
    KeyName = "resourceName",
    SegmentName = "webPubSub",
    NamePattern = "^[a-zA-Z][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$"
  >;

  /**
   * The billing information of the resource.
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-resource-invalid-envelope-property" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  sku?: ResourceSku;

  #suppress "@azure-tools/typespec-azure-core/no-private-usage" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  #suppress "@azure-tools/typespec-azure-core/no-private-usage" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-resource-invalid-envelope-property" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  @doc("The resource-specific properties for this resource.")
  @Azure.ResourceManager.Private.armResourcePropertiesOptionality(true)
  properties?: WebPubSubProperties;

  /**
   * The kind of the service
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-resource-invalid-envelope-property" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  @visibility(Lifecycle.Read, Lifecycle.Create)
  kind?: ServiceKind;

  /**
   * A class represent managed identities used for request and response
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-resource-invalid-envelope-property" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  identity?: ManagedIdentity;
}



/**
 * A class that describes the properties of the resource
 */
model WebPubSubProperties {
  /**
   * Provisioning state of the resource.
   */
  @visibility(Lifecycle.Read)
  provisioningState?: ProvisioningState;

  /**
   * The publicly accessible IP of the resource.
   */
  #suppress "@azure-tools/typespec-azure-core/casing-style" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  @visibility(Lifecycle.Read)
  externalIP?: string;

  /**
   * FQDN of the service instance.
   */
  @visibility(Lifecycle.Read)
  hostName?: string;

  /**
   * The publicly accessible port of the resource which is designed for browser/client side usage.
   */
  @visibility(Lifecycle.Read)
  publicPort?: int32;

  /**
   * The publicly accessible port of the resource which is designed for customer server side usage.
   */
  @visibility(Lifecycle.Read)
  serverPort?: int32;

  /**
   * Version of the resource. Probably you need the same or higher version of client SDKs.
   */
  @visibility(Lifecycle.Read)
  version?: string;

  /**
   * Private endpoint connections to the resource.
   */
  @visibility(Lifecycle.Read)
  @OpenAPI.extension("x-ms-identifiers", #[])
  privateEndpointConnections?: PrivateEndpointConnection[];

  /**
   * The list of shared private link resources.
   */
  @visibility(Lifecycle.Read)
  @OpenAPI.extension("x-ms-identifiers", #[])
  sharedPrivateLinkResources?: SharedPrivateLinkResource[];

  /**
   * TLS settings for the resource
   */
  tls?: WebPubSubTlsSettings;

  /**
   * Deprecated.
   */
  @visibility(Lifecycle.Read)
  hostNamePrefix?: string;

  /**
   * Live trace configuration of a Microsoft.SignalRService resource.
   */
  liveTraceConfiguration?: LiveTraceConfiguration;

  /**
   * Resource log configuration of a Microsoft.SignalRService resource.
   */
  resourceLogConfiguration?: ResourceLogConfiguration;

  /**
   * Network ACLs for the resource
   */
  #suppress "@azure-tools/typespec-azure-core/casing-style" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  networkACLs?: WebPubSubNetworkACLs;

  /**
   * Application firewall settings for the resource
   */
  applicationFirewall?: ApplicationFirewallSettings;

  /**
   * Enable or disable public network access. Default to "Enabled".
   * When it's Enabled, network ACLs still apply.
   * When it's Disabled, public network access is always disabled no matter what you set in network ACLs.
   */
  publicNetworkAccess?: string = "Enabled";

  /**
   * DisableLocalAuth
   * Enable or disable local auth with AccessKey
   * When set as true, connection with AccessKey=xxx won't work.
   */
  disableLocalAuth?: boolean = false;

  /**
   * DisableLocalAuth
   * Enable or disable aad auth
   * When set as true, connection with AuthType=aad won't work.
   */
  disableAadAuth?: boolean = false;

  /**
   * Enable or disable the regional endpoint. Default to "Enabled".
   * When it's Disabled, new connections will not be routed to this endpoint, however existing connections will not be affected.
   * This property is replica specific. Disable the regional endpoint without replica is not allowed.
   */
  regionEndpointEnabled?: string = "Enabled";

  /**
   * Stop or start the resource.  Default to "False".
   * When it's true, the data plane of the resource is shutdown.
   * When it's false, the data plane of the resource is started.
   */
  resourceStopped?: string = "false";

  /**
   * SocketIO settings for the resource
   */
  #suppress "@azure-tools/typespec-azure-core/casing-style" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  socketIO?: WebPubSubSocketIOSettings;
}

@armResourceOperations
interface WebPubSubResources {
  /**
   * Get the resource and its properties.
   */
  get is ArmResourceRead<WebPubSubResource>;

  /**
   * Create or update a resource.
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-put-operation-response-codes" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  #suppress "@azure-tools/typespec-azure-resource-manager/lro-location-header" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  createOrUpdate is ArmResourceCreateOrReplaceAsync<
    WebPubSubResource,
    Response = ArmResponse<WebPubSubResource> | ArmResourceCreatedResponse<
      WebPubSubResource,
      LroHeaders = ArmAsyncOperationHeader<FinalResult = WebPubSubResource>
    > | {
      @statusCode statusCode: 202;
    }
  >;

  /**
   * Operation to update an exiting resource.
   */
  @patch(#{ implicitOptionality: false })
  update is ArmCustomPatchAsync<
    WebPubSubResource,
    PatchModel = WebPubSubResource
  >;

  /**
   * Operation to delete a resource.
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-delete-operation-response-codes" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  delete is ArmResourceDeleteWithoutOkAsync<
    WebPubSubResource,
    Response =
      | OkResponse
      | ArmDeletedResponse
      | ArmDeleteAcceptedLroResponse
      | ArmDeletedNoContentResponse
  >;

  /**
   * Handles requests to list all resources in a resource group.
   */
  listByResourceGroup is ArmResourceListByParent<
    WebPubSubResource,
    Response = ArmResponse<WebPubSubResourceList>
  >;

  /**
   * Handles requests to list all resources in a subscription.
   */
  listBySubscription is ArmListBySubscription<
    WebPubSubResource,
    Response = ArmResponse<WebPubSubResourceList>
  >;

  /**
   * Get the access keys of the resource.
   */
  listKeys is ArmResourceActionSync<WebPubSubResource, void, WebPubSubKeys>;

  /**
   * Regenerate the access key for the resource. PrimaryKey and SecondaryKey cannot be regenerated at the same time.
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-post-operation-response-codes" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  #suppress "@azure-tools/typespec-azure-resource-manager/no-response-body" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  regenerateKey is ArmResourceActionSync<
    WebPubSubResource,
    RegenerateKeyParameters,
    Response = WebPubSubKeys | (ArmAcceptedLroResponse & {
      @bodyRoot
      _: WebPubSubKeys;
    })
  >;

  /**
   * Operation to restart a resource.
   */
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-post-operation-response-codes" "FIXME: Update justification, follow aka.ms/tsp/conversion-fix for details"
  restart is ArmResourceActionAsync<WebPubSubResource, void, void>;

  /**
   * List all available skus of the resource.
   */
  @get
  @action("skus")
  listSkus is ArmResourceActionSync<
    WebPubSubResource,
    void,
    ArmResponse<SkuList>
  >;

  /**
   * Get the private link resources that need to be created for a resource.
   */
  @get
  @action("privateLinkResources")
  list is ArmResourceActionSync<
    WebPubSubResource,
    void,
    ArmResponse<PrivateLinkResourceList>
  >;
}

@@maxLength(WebPubSubResource.name, 63);
@@minLength(WebPubSubResource.name, 3);
@@doc(WebPubSubResource.name, "The name of the resource.");
@@doc(WebPubSubResource.properties,
  "A class that describes the properties of the resource"
);
@@doc(WebPubSubResources.createOrUpdate::parameters.resource,
  "Parameters for the create or update operation"
);
@@doc(WebPubSubResources.update::parameters.properties,
  "Parameters for the update operation"
);
@@doc(WebPubSubResources.regenerateKey::parameters.body,
  "Parameter that describes the Regenerate Key Operation."
);
