package coinbase

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
)

type coinbaseAPIResourceConfig struct {
	APIs []coinbaseAPI `json:"apis"`
}

type coinbaseAPI struct {
	APIName   string     `json:"api_name"`
	Resources []resource `json:"resources"`
}

type resource struct {
	Name    string   `json:"name"`
	Actions []action `json:"actions"`
}

type action struct {
	Name               string `json:"name"`
	RequiredPermission string `json:"required_permission"`
}

//go:embed resources.json
var resourceConfigBytes []byte

func readInResources() (*coinbaseAPIResourceConfig, error) {
	resourceConfig := coinbaseAPIResourceConfig{}
	if err := json.Unmarshal(resourceConfigBytes, &resourceConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resources config: %w", err)
	}
	return &resourceConfig, nil
}

func createBindings(info *secretInfo, resource *analyzers.Resource) []analyzers.Binding {
	bindings := []analyzers.Binding{}
	for perm := range info.Permissions {
		bindings = append(
			bindings,
			analyzers.Binding{
				Resource: *resource,
				Permission: analyzers.Permission{
					Value: PermissionStrings[perm],
				},
			},
		)
	}
	return bindings
}

func createAccountResource(account account) analyzers.Resource {
	return analyzers.Resource{
		Name:               account.Name,
		FullyQualifiedName: "account/" + account.UUID,
		Type:               "account",
		Metadata: map[string]any{
			"currency":          account.Currency,
			"default":           account.Default,
			"active":            account.Active,
			"type":              account.Type,
			"ready":             account.Ready,
			"retailPortfolioID": account.RetailPortfolioID,
			"platform":          account.Platform,
			"availableBalance": map[string]any{
				"value":    account.AvailableBalance.Value,
				"currency": account.AvailableBalance.Currency,
			},
			"hold": map[string]any{
				"value":    account.Hold.Value,
				"currency": account.Hold.Currency,
			},
			"createdAt": account.CreatedAt,
			"deletedAt": account.DeletedAt,
		},
	}
}

func createPortfolioResource(portfolio portfolio) analyzers.Resource {
	return analyzers.Resource{
		Name:               portfolio.Name,
		FullyQualifiedName: "portfolio/" + portfolio.UUID,
		Type:               "portfolio",
		Metadata: map[string]any{
			"type":    portfolio.Type,
			"deleted": portfolio.Deleted,
		},
	}
}

func createPaymentMethodResource(paymentMethod paymentMethod) analyzers.Resource {
	return analyzers.Resource{
		Name:               paymentMethod.Name,
		FullyQualifiedName: "payment_method/" + paymentMethod.ID,
		Type:               "payment_method",
		Metadata: map[string]any{
			"type":          paymentMethod.Type,
			"currency":      paymentMethod.Currency,
			"verified":      paymentMethod.Verified,
			"allowBuy":      paymentMethod.AllowBuy,
			"allowSell":     paymentMethod.AllowSell,
			"allowDeposit":  paymentMethod.AllowDeposit,
			"allowWithdraw": paymentMethod.AllowWithdraw,
			"createdAt":     paymentMethod.CreatedAt,
			"updatedAt":     paymentMethod.UpdatedAt,
		},
	}
}

func createOrderResource(order order) analyzers.Resource {
	return analyzers.Resource{
		Name:               order.OrderID,
		FullyQualifiedName: "order/" + order.OrderID,
		Type:               "order",
		Metadata: map[string]any{
			"side":                  order.Side,
			"status":                order.Status,
			"productID":             order.ProductID,
			"userID":                order.UserID,
			"timeInForce":           order.TimeInForce,
			"createdTime":           order.CreatedTime,
			"filledSize":            order.FilledSize,
			"averageFilledPrice":    order.AverageFilledPrice,
			"fee":                   order.Fee,
			"numberOfFills":         order.NumberOfFills,
			"filledValue":           order.FilledValue,
			"pendingCancel":         order.PendingCancel,
			"sizeInQuote":           order.SizeInQuote,
			"totalFees":             order.TotalFees,
			"sizeInclusiveOfFees":   order.SizeInclusiveOfFees,
			"totalValueAfterFees":   order.TotalValueAfterFees,
			"triggerStatus":         order.TriggerStatus,
			"orderType":             order.OrderType,
			"rejectReason":          order.RejectReason,
			"settled":               order.Settled,
			"productType":           order.ProductType,
			"rejectMessage":         order.RejectMessage,
			"cancelMessage":         order.CancelMessage,
			"orderPlacementSource":  order.OrderPlacementSource,
			"outstandingHoldAmount": order.OutstandingHoldAmount,
			"isLiquidation":         order.IsLiquidation,
			"lastFillTime":          order.LastFillTime,
			"leverage":              order.Leverage,
			"marginType":            order.MarginType,
			"retailPortfolioID":     order.RetailPortfolioID,
			"originatingOrderID":    order.OriginatingOrderID,
			"attachedOrderID":       order.AttachedOrderID,
		},
	}
}

func createWalletResource(wallet wallet) analyzers.Resource {
	return analyzers.Resource{
		Name:               wallet.ID,
		FullyQualifiedName: "wallet/" + wallet.ID,
		Type:               "wallet",
		Metadata: map[string]any{
			"networkID":          wallet.NetworkID,
			"serverSignerStatus": wallet.ServerSignerStatus,
		},
	}
}

func createAddressResource(address address) analyzers.Resource {
	return analyzers.Resource{
		Name:               address.AddressID,
		FullyQualifiedName: "wallet/" + address.WalletID + "/address/" + address.AddressID,
		Type:               "address",
		Metadata: map[string]any{
			"walletID":  address.WalletID,
			"networkID": address.NetworkID,
			"publicKey": address.PublicKey,
		},
	}
}
