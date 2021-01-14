package keeper

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"github.com/althea-net/peggy/module/x/peggy/types"
)

func TestQueryParams(t *testing.T) {
	input := CreateTestEnv(t)
	ctx := input.Context

	var expectedParams = TestingPeggyParams

	testCases := []struct {
		msg      string
		malleate func()
	}{
		{
			"default custom ",
			func() {},
		},
		{
			"default",
			func() {
				params := types.DefaultParams()
				expectedParams = *params
				input.PeggyKeeper.SetParams(ctx, expectedParams)
			},
		},
	}

	for _, tc := range testCases {

		tc.malleate()
		ctx := sdk.WrapSDKContext(ctx)

		res, err := input.QueryClient.Params(ctx, &types.QueryParamsRequest{})
		require.NoError(t, err, tc.msg)
		require.NotNil(t, res, tc.msg)
		require.Equal(t, &expectedParams, res.Params, tc.msg)
	}
}

func TestCurrentValset(t *testing.T) {
	input := CreateTestEnv(t)
	ctx := input.Context
	c := sdk.WrapSDKContext(ctx)

	res, err := input.QueryClient.CurrentValset(c, &types.QueryCurrentValsetRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
}

func TestValsetRequest(t *testing.T) {
	input := CreateTestEnv(t)
	ctx := input.Context

	var (
		expectedValset = &types.Valset{}
		req            = &types.QueryValsetRequestRequest{}
	)

	testCases := []struct {
		msg        string
		malleate   func()
		expectPass bool
	}{
		{
			"zero height request",
			func() {},
			false,
		},
		{
			"custom height",
			func() {
				req = &types.QueryValsetRequestRequest{
					Nonce: 10,
				}

				ctx = ctx.WithBlockHeight(int64(req.Nonce))
				input.PeggyKeeper.SetValsetRequest(ctx)
				expectedValset = &types.Valset{
					Nonce:  10,
					Height: 10,
				}
			},
			true,
		},
	}

	for _, tc := range testCases {

		tc.malleate()
		ctx := sdk.WrapSDKContext(ctx)

		res, err := input.QueryClient.ValsetRequest(ctx, req)
		if tc.expectPass {
			require.NoError(t, err, tc.msg)
			require.NotNil(t, res, tc.msg)
			require.Equal(t, expectedValset, res.Valset, tc.msg)
		} else {
			require.Error(t, err, tc.msg)
			require.Nil(t, res, tc.msg)
		}
	}
}
