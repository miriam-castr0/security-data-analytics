import logging
import os

import pandas as pd
from dash import html, dash
import plotly.graph_objs as go
from dash import dcc, dash_table
from dash.dependencies import Input, Output

from src.utils.constants import TIMESTAMP_KEY

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FLASK_HOST = os.environ.get('FLASK_RUN_HOST')
PORT = os.environ.get("PORT")


class DashApplication:
    def __init__(self):
        self.app = dash.Dash(__name__)
        self.server_running = False
        self.__setup_layout()
        self.__register_callbacks()

    def run_server(self):
        self.server_running = True
        self.app.run_server(host=FLASK_HOST, port=PORT, debug=False)

    def stop_server(self):
        if self.server_running:
            self.server_running = False

    def __setup_layout(self):
        # Define el layout de la aplicación Dash
        self.app.layout = html.Div([
            html.H1("DDoS attack detection"),
            dcc.Tabs(id="tabs", value='graph-tab', children=[
                dcc.Tab(label='DDoS Count', value='graph-tab'),
                dcc.Tab(label='DDoS Rate Over Time', value='time-graph-tab'),
                dcc.Tab(label = 'DDoS Rate by Type', value='rate-type-graph-tab'),
                dcc.Tab(label='Model Test Results', value='model-results-tab'),

            ]),
            html.Div(id='tabs-content'),
            html.Div(id='dropdown-container'),  # Placeholder for dropdown
        ])

    def __register_callbacks(self):
        self.app.callback(
            Output('tabs-content', 'children'),
            [Input('tabs', 'value')]
        )(self.__render_content)

        self.app.callback(
            Output('dropdown-container', 'children'),
            [Input('tabs', 'value')]
        )(self.__render_dropdown)

        self.app.callback(
            Output('ddos-count-graph', 'figure'),
            [Input('dropdown', 'value')]
        )(self.__update_ddos_count_graph)

        self.app.callback(
            Output('ddos-rate-time-graph', 'figure'),
            [Input('tabs', 'value')]
        )(self.__update_ddos_rate_time_graph)

        self.app.callback(
            Output('model-test-results-graph', 'children'),
            [Input('tabs', 'value')]
        )(self.__update_model_test_results_graph)

        self.app.callback(
            Output('ddos-rate-type-graph', 'children'),
            [Input('tabs', 'value')]
        )(self._update_ddos_rate_type_graph)

    def __render_content(self, tab):
        if tab == 'graph-tab':
            return dcc.Graph(id='ddos-count-graph')
        elif tab == 'time-graph-tab':
            return dcc.Graph(id='ddos-rate-time-graph')
        elif tab == 'rate-type-graph-tab':
            return html.Div(id='ddos-rate-type-graph')
        elif tab == 'model-results-tab':
            return html.Div(id='model-test-results-graph')

    def __render_dropdown(self, tab):
        if tab == 'graph-tab':
            return dcc.Dropdown(
                id='dropdown',
                options=[
                    {'label': 'IP Source', 'value': 'source_ip'},
                    {'label': 'IP Destination', 'value': 'dest_ip'},
                    {'label': 'Protocol', 'value': 'protocol'},
                ],
                value='source_ip'
            )
        else:
            return None
    
    def _update_ddos_rate_type_graph(self, tab):
        if tab == 'rate-type-graph-tab' and self.ddos_rate_type_list is not None:
            fig = {
                'data': [
                    {
                        'x': self.ddos_rate_type_list['class'],
                        'y': self.ddos_rate_type_list['rate'],
                        'mode': 'markers',
                        'type': 'scatter',
                        'name': 'Percentagem',
                        'customdata': [
                            f"Total Flows: {total_flows}<br>DDoS Flows: {ddos_flows}"
                            for total_flows, ddos_flows in zip(self.ddos_rate_type_list['total_flows'], self.ddos_rate_type_list['ddos_flows_by_class'])
                        ],
                        'text':self.ddos_rate_type_list['timestamp'],
                        'hovertemplate': 'Class: %{x}<br>Rate: %{y}<br>%{customdata}<br>Timestamp: %{text}<extra></extra>'
                    }
                ],
                'layout': {
                    'title': 'Rate by Class',
                    'xaxis': {'title': 'Classe'},
                    'yaxis': {'title': 'Rate'}
                }
            }
            table = self.create_table()
            return html.Div([dcc.Graph(figure=fig), table])
        else:
            return {}


    def __update_ddos_count_graph(self, selected_value='attacker_ip'):
        if self.results is None:
            return {}

        # Filter results based on the selected parameter
        if selected_value in self.results.columns:
            filtered_results = self.results[self.results[selected_value].notnull()]
        else:
            # Trate o caso em que a chave não existe
            return {}
        # Count DDoS for that parameter
        ddos_counts = filtered_results.groupby(selected_value)['ddos_status'].sum().reset_index()
        # Sort ports alphanumeric
        if selected_value in ['protocol']:
            ddos_counts[selected_value] = ddos_counts[selected_value].astype(str)
            ddos_counts[selected_value] = ddos_counts[selected_value].str.pad(5, side='left', fillchar='0')
            ddos_counts = ddos_counts.sort_values(by=selected_value)
            ddos_counts[selected_value] = ddos_counts[selected_value].astype(int).astype(str)

        red = '#C12200'
        fig = go.Figure(
            data=[go.Bar(x=ddos_counts[selected_value], y=ddos_counts['ddos_status'], text=ddos_counts['ddos_status'],  marker_color=red)])
        fig.update_layout(yaxis_type="log")
        fig.update_layout(title='DDoS count by {}'.format(selected_value))
        fig.update_yaxes(tickmode='linear', dtick=1)
        fig.update_yaxes(title='DDoS count')
        fig.update_traces(hovertemplate='DDoS count: %{y}')
        return fig

    def __update_ddos_rate_time_graph(self, tab):
        if tab == 'time-graph-tab' and self.ddos_rate_list is not None:
            # Create datetime column from timestamp
            self.ddos_rate_list['datetime'] = pd.to_datetime(self.ddos_rate_list[TIMESTAMP_KEY])

            # Extract date and hour from datetime
            self.ddos_rate_list['date'] = self.ddos_rate_list['datetime'].dt.date
            self.ddos_rate_list['hour'] = self.ddos_rate_list['datetime'].dt.hour

            # Convert ddos_rate to percentage
            self.ddos_rate_list['ddos_rate'] = pd.to_numeric(self.ddos_rate_list['ddos_rate'], errors='coerce').fillna(0)
            self.ddos_rate_list['ddos_rate_percentage'] = self.ddos_rate_list['ddos_rate'] * 100
            logger.info(f"ddos graph {self.ddos_rate_list['ddos_rate']}")
            fig = go.Figure(data=[
                go.Scatter(x=self.ddos_rate_list['datetime'], y=self.ddos_rate_list['ddos_rate_percentage'],
                            mode='lines+markers', hoverinfo='text+x+y',  # Informações que aparecerão ao passar o mouse
                            text=[
                                f'DDoS Flow/Total Flows: {ddos}<br>/{total}<br>'
                                for ddos, total in zip(self.ddos_rate_list['ddos_flows'],
                                                    self.ddos_rate_list['total_flows'])
                            ],
                            marker=dict(
                                size=10,
                                color='blue',
                                opacity=0.8
                            ))])
            fig.update_layout(title='DDoS rate over time')
            fig.update_yaxes(title='DDoS rate (%)')
            return fig
        else:
            return {}

    def __update_model_test_results_graph(self, tab):
        if tab == 'model-results-tab' and self.model_test_results_lucid is not None and self.model_test_results_rf is not None:
            # First figure
            fig1 = go.Figure()
            metrics1 = ['accuracy', 'f1', 'true_positive_rate', 'false_positive_rate','true_negative_rate', 'false_negative_rate', 'prediction_time', 'precision', 'recall', 'mse', 'auc']
            for metric in metrics1:
                fig1.add_trace(go.Scatter(x=self.model_test_results_lucid[TIMESTAMP_KEY], y=self.model_test_results_lucid[metric],
                                        mode='markers', name=metric.capitalize(),
                                        text=[f"Data Source: {source}" for source in
                                                self.model_test_results_lucid['data_source']],
                                        hoverinfo="x+y+text"))
            fig1.update_layout(title='LUCID Model Test Results', xaxis_title=TIMESTAMP_KEY, yaxis_title='Metric Value')

            # Second figure
            fig2 = go.Figure()
            metrics2 = ['accuracy', 'f1', 'prediction_time', 'precision', 'recall', 'mse']
            for metric in metrics2:
                fig2.add_trace(go.Scatter(x=self.model_test_results_rf[TIMESTAMP_KEY], y=self.model_test_results_rf[metric],
                                        mode='markers', name=metric.capitalize(),
                                        text=[f"Data Source: {source}" for source in
                                                self.model_test_results_rf['data_source']],
                                        hoverinfo="x+y+text"))
            fig2.update_layout(title='Random Forest Model Test Results', xaxis_title=TIMESTAMP_KEY, yaxis_title='Metric Value')

            return html.Div([
                dcc.Graph(figure=fig1),
                dcc.Graph(figure=fig2)
            ])
        else:
            return {}
        
    def create_table(self):
        return dash_table.DataTable(
            id='table',
            columns=[{"name": i, "id": i} for i in self.ddos_rate_type_list.columns],
            data=self.ddos_rate_type_list.to_dict('records'),
            style_table={'overflowX': 'auto'},
            style_header={
                'backgroundColor': 'rgb(230, 230, 230)',
                'color': 'black',
                'fontWeight': 'bold',
                'height': '30px'
            },
            style_cell={
                'backgroundColor': 'rgb(255, 255, 255)',
                'color': 'black',
                'textAlign': 'left',
                'padding': '8px',
                'height': '30px'
            },
            style_data={
                'border': '1px solid grey'
            },
            page_size=10
        )
